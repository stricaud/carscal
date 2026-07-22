//! The terminal UI: a Wireshark-style three-pane layout driven by gtcaca.
//!
//! Layout (top to bottom):
//!   - a hint/menu line
//!   - the display-filter box
//!   - the packet list (a virtual [`gtcaca::Table`])
//!   - the packet detail tree (left) + hex byte pane (right)
//!   - a status bar
//!
//! We drive our own event loop on the global display ([`gtcaca::poll_key`]) and
//! keep selection state authoritative in [`AppState`], syncing the table cursor
//! with [`gtcaca::Table::set_current`].

use std::cell::RefCell;
use std::os::raw::c_void;
use std::rc::Rc;

use gtcaca::{key, Gtcaca, Hexview, Label, Menu, Statusbar, Table, TableModel, Tree, TreeModel, Widget};
use libpcapng::ffi::pcapng_field_t;
use libpcapng::{Dissection, Field};

use crate::colorrules::{caca, ColorRules};
use crate::dissect;
use crate::filter::Filter;
use crate::model::Capture;

/// Inner padding, in character cells, between a window's border and its content
/// (passed to [`gtcaca::Window::content`]). `0` means flush against the border.
const PAD: i32 = 1;
/// No padding — content spans the full inner width (e.g. the filter entry).
const NO_PAD: i32 = 0;

/// Which pane currently has keyboard focus.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Filter,
    Find,
    DecodeAs,
    OpenFile,
    Table,
    Tree,
    Hex,
}

// ── menu action dispatch ──────────────────────────────────────────────────────
//
// gtcaca menu items invoke a C action callback. We register one callback that
// stashes the item's action id (passed as userdata) in a thread-local, then the
// event loop reads and dispatches it. Single-threaded, so a Cell is enough.

mod act {
    pub const OPEN: i32 = 1;
    pub const SAVE: i32 = 2;
    pub const QUIT: i32 = 3;
    pub const FIND: i32 = 4;
    pub const FIND_NEXT: i32 = 5;
    pub const FIND_PREV: i32 = 6;
    pub const GOTO: i32 = 7;
    pub const MARK: i32 = 8;
    pub const COLORIZE: i32 = 9;
    pub const FOLLOW: i32 = 10;
    pub const DECODE: i32 = 11;
    pub const CONV: i32 = 12;
    pub const APPLY_FILTER: i32 = 13;
    pub const APPLY_COLUMN: i32 = 14;
    pub const IOGRAPH: i32 = 15;
    pub const STATS_CONV: i32 = 16;
    pub const STATS_PROTO: i32 = 17;
    pub const ABOUT: i32 = 18;
    pub const CAPTURE_START: i32 = 19;
    pub const CAPTURE_STOP: i32 = 20;
    pub const CAPTURE_FOLLOW: i32 = 21;
    pub const RELOAD: i32 = 22;
    pub const UNMARK_ALL: i32 = 23;
    pub const RESET_COLUMNS: i32 = 24;
    pub const STATS_ENDPOINTS: i32 = 25;
    pub const COLOR_RULES: i32 = 26;
    pub const DECODERS: i32 = 27;
    pub const EXPORT_HTTP: i32 = 28;
    pub const EXPORT_SMB: i32 = 29;
    pub const STATS_ENTITY: i32 = 30;
}

thread_local! {
    static PENDING: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

extern "C" fn menu_cb(userdata: *mut c_void) {
    PENDING.with(|p| p.set(userdata as i32));
}

fn take_pending() -> i32 {
    PENDING.with(|p| {
        let v = p.get();
        p.set(0);
        v
    })
}

/// The menu bar plus the (entry, item) coordinates of items that require a
/// loaded capture, so they can be greyed out when there is none.
struct Menus {
    menu: Menu,
    needs_capture: Vec<(i32, i32)>,
    /// (entry, item) of the Capture Start / Stop / Follow-Newest items, greyed
    /// depending on whether a live capture is running.
    cap_start: (i32, i32),
    cap_stop: (i32, i32),
    cap_follow: (i32, i32),
}

/// Build the Wireshark-style menu bar (File / Edit / View / Capture / Analyze /
/// Statistics / Help), each item wired to an [`act`] id via [`menu_cb`].
fn build_menu() -> Menus {
    let m = Menu::new();
    let id = |a: i32| a as *mut c_void;
    let mut needs: Vec<(i32, i32)> = Vec::new();

    let file = m.add_entry("File");
    m.add_item(file, "Open\u{2026}", "F2", menu_cb, id(act::OPEN));
    needs.push((file, m.add_item(file, "Reload", "", menu_cb, id(act::RELOAD))));
    needs.push((file, m.add_item(file, "Save As\u{2026}", "^S", menu_cb, id(act::SAVE))));
    m.add_separator(file);
    needs.push((file, m.add_item(file, "Export HTTP Objects\u{2026}", "", menu_cb, id(act::EXPORT_HTTP))));
    needs.push((file, m.add_item(file, "Export SMB Objects\u{2026}", "", menu_cb, id(act::EXPORT_SMB))));
    m.add_separator(file);
    m.add_item(file, "Quit", "^Q", menu_cb, id(act::QUIT));

    let edit = m.add_entry("Edit");
    needs.push((edit, m.add_item(edit, "Find Packet\u{2026}", "^F", menu_cb, id(act::FIND))));
    needs.push((edit, m.add_item(edit, "Find Next", "n", menu_cb, id(act::FIND_NEXT))));
    needs.push((edit, m.add_item(edit, "Find Previous", "N", menu_cb, id(act::FIND_PREV))));
    m.add_separator(edit);
    needs.push((edit, m.add_item(edit, "Go to Packet\u{2026}", "^G", menu_cb, id(act::GOTO))));
    m.add_separator(edit);
    needs.push((edit, m.add_item(edit, "Mark/Unmark Packet", "m", menu_cb, id(act::MARK))));
    needs.push((edit, m.add_item(edit, "Unmark All", "", menu_cb, id(act::UNMARK_ALL))));

    let view = m.add_entry("View");
    needs.push((view, m.add_item(view, "Colorize Packet List", "C", menu_cb, id(act::COLORIZE))));
    m.add_item(view, "Coloring Rules\u{2026}", "", menu_cb, id(act::COLOR_RULES));

    let capture = m.add_entry("Capture");
    let cap_start = m.add_item(capture, "Start\u{2026}", "", menu_cb, id(act::CAPTURE_START));
    let cap_stop = m.add_item(capture, "Stop", "", menu_cb, id(act::CAPTURE_STOP));
    let cap_follow = m.add_item(capture, "Follow Newest", "f", menu_cb, id(act::CAPTURE_FOLLOW));

    let analyze = m.add_entry("Analyze");
    needs.push((analyze, m.add_item(analyze, "Apply as Filter", "=", menu_cb, id(act::APPLY_FILTER))));
    needs.push((analyze, m.add_item(analyze, "Apply as Column", "|", menu_cb, id(act::APPLY_COLUMN))));
    needs.push((analyze, m.add_item(analyze, "Remove Custom Columns", "", menu_cb, id(act::RESET_COLUMNS))));
    needs.push((analyze, m.add_item(analyze, "Conversation Filter", "c", menu_cb, id(act::CONV))));
    m.add_separator(analyze);
    needs.push((analyze, m.add_item(analyze, "Follow TCP/UDP Stream", "S", menu_cb, id(act::FOLLOW))));
    needs.push((analyze, m.add_item(analyze, "Decode As\u{2026}", "D", menu_cb, id(act::DECODE))));
    m.add_item(analyze, "Decoders\u{2026}", "", menu_cb, id(act::DECODERS));

    let stats = m.add_entry("Statistics");
    needs.push((stats, m.add_item(stats, "IO Graph", "I", menu_cb, id(act::IOGRAPH))));
    needs.push((stats, m.add_item(stats, "Conversations (NetFlow)", "", menu_cb, id(act::STATS_CONV))));
    needs.push((stats, m.add_item(stats, "Endpoints", "", menu_cb, id(act::STATS_ENDPOINTS))));
    needs.push((stats, m.add_item(stats, "Entity Explorer\u{2026}", "", menu_cb, id(act::STATS_ENTITY))));
    needs.push((stats, m.add_item(stats, "Protocol Hierarchy", "", menu_cb, id(act::STATS_PROTO))));

    let help = m.add_entry("Help");
    m.add_item(help, "About carscal", "", menu_cb, id(act::ABOUT));

    Menus {
        menu: m,
        needs_capture: needs,
        cap_start: (capture, cap_start),
        cap_stop: (capture, cap_stop),
        cap_follow: (capture, cap_follow),
    }
}

impl Menus {
    /// Grey out capture-dependent items when there is no loaded capture.
    fn update(&self, has_capture: bool) {
        for &(e, i) in &self.needs_capture {
            self.menu.set_item_enabled(e, i, has_capture);
        }
    }

    /// Toggle the Capture menu for a running live capture: Stop / Follow enabled,
    /// Start greyed (and the reverse when idle).
    fn set_capturing(&self, capturing: bool) {
        self.menu.set_item_enabled(self.cap_start.0, self.cap_start.1, !capturing);
        self.menu.set_item_enabled(self.cap_stop.0, self.cap_stop.1, capturing);
        self.menu.set_item_enabled(self.cap_follow.0, self.cap_follow.1, capturing);
    }
}

/// Everything the models and the event loop share.
struct AppState {
    cap: Capture,
    /// Packet indices passing the current filter (row → packet index).
    rows: Vec<usize>,
    /// Selected row within `rows`.
    sel: usize,
    /// Dissection of the selected packet (keeps its field pointers alive).
    dissection: Option<Dissection>,
    /// Flat node table for the detail tree; handle id `n` → `nodes[n-1]`
    /// (id 0 is the dissection root). Rebuilt whenever `dissection` changes.
    nodes: Vec<*mut pcapng_field_t>,
    /// The current filter text and its compiled form.
    filter_text: String,
    filter: Filter,
    first_ts_us: u64,
    status: String,
    colors: ColorRules,
    /// Extra packet-list columns added via Apply-as-Column (`|`): field abbrevs.
    extra_columns: Vec<String>,
    /// Find state (`^F` / `n` / `N`).
    find_text: String,
    find_needle: Option<crate::find::Needle>,
    /// Decode-As input buffer (`D`).
    decode_text: String,
    /// File-open path input buffer (`F2` / `^O`).
    open_text: String,
}

impl AppState {
    fn selected_pkt(&self) -> Option<usize> {
        self.rows.get(self.sel).copied()
    }

    /// Recompute `rows` from the current filter.
    fn apply_filter(&mut self) {
        let match_all = self.filter.is_match_all();
        self.rows.clear();
        for (i, pkt) in self.cap.pkts.iter().enumerate() {
            if match_all {
                self.rows.push(i);
            } else if let Some(d) = dissect::dissect(pkt) {
                if self.filter.eval(&d.root()) {
                    self.rows.push(i);
                }
            }
        }
        if self.sel >= self.rows.len() {
            self.sel = self.rows.len().saturating_sub(1);
        }
    }

    /// Rebuild the dissection + node table for the current selection.
    fn refresh_selection(&mut self) {
        self.nodes.clear();
        self.dissection = None;
        if let Some(idx) = self.selected_pkt() {
            if let Some(d) = dissect::dissect(&self.cap.pkts[idx]) {
                // Flatten every node so the tree can address them by stable id.
                let root = d.root_ptr();
                unsafe { collect_nodes(root, &mut self.nodes) };
                self.dissection = Some(d);
            }
        }
    }
}

/// Depth-first flatten of the field tree into a pointer table.
unsafe fn collect_nodes(node: *mut pcapng_field_t, out: &mut Vec<*mut pcapng_field_t>) {
    if node.is_null() {
        return;
    }
    let mut child = (*node).children;
    while !child.is_null() {
        out.push(child);
        collect_nodes(child, out);
        child = (*child).next;
    }
}

// ── models ───────────────────────────────────────────────────────────────────

struct PacketTable(Rc<RefCell<AppState>>);

impl TableModel for PacketTable {
    fn row_count(&self) -> i64 {
        self.0.borrow().rows.len() as i64
    }

    fn headers(&self) -> Vec<String> {
        let mut h: Vec<String> = ["No.", "Time", "Source", "Destination", "Proto", "Len", "Info"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        h.extend(self.0.borrow().extra_columns.iter().cloned());
        h
    }

    fn row_color(&self, row: i64) -> Option<(u8, u8)> {
        let st = self.0.borrow();
        let idx = *st.rows.get(row as usize)?;
        let pkt = &st.cap.pkts[idx];
        // A marked packet is always visually unmistakable (overrides rules).
        if pkt.marked {
            return Some((caca::WHITE, caca::BLACK));
        }
        if !st.colors.is_enabled() {
            return None;
        }
        let d = dissect::dissect(pkt)?;
        st.colors.match_row(&d.root())
    }

    fn cell(&self, row: i64, col: i32) -> String {
        let mut st = self.0.borrow_mut();
        let first = st.first_ts_us;
        let idx = match st.rows.get(row as usize).copied() {
            Some(i) => i,
            None => return String::new(),
        };
        // Extra (Apply-as-Column) fields: dissect and pull the field's value.
        if col >= 7 {
            let abbrev = match st.extra_columns.get((col - 7) as usize) {
                Some(a) => a.clone(),
                None => return String::new(),
            };
            return match dissect::dissect(&st.cap.pkts[idx]) {
                Some(d) => d
                    .root()
                    .find(&abbrev)
                    .map(|f| dissect::field_value(&f))
                    .unwrap_or_default(),
                None => String::new(),
            };
        }
        let s = dissect::summarize(&mut st.cap.pkts[idx]);
        let pkt = &st.cap.pkts[idx];
        match col {
            0 => pkt.number.to_string(),
            1 => format!("{:.6}", (pkt.ts_us.saturating_sub(first)) as f64 / 1_000_000.0),
            2 => s.src,
            3 => s.dst,
            4 => s.proto,
            5 => pkt.origlen.to_string(),
            6 => s.info,
            _ => String::new(),
        }
    }
}

struct DetailTree(Rc<RefCell<AppState>>);

impl DetailTree {
    /// Resolve a tree handle to a field pointer (null handle = dissection root).
    fn resolve(st: &AppState, node: *mut c_void) -> *mut pcapng_field_t {
        let id = node as usize;
        if id == 0 {
            return match &st.dissection {
                Some(d) => d.root_ptr(),
                None => std::ptr::null_mut(),
            };
        }
        st.nodes.get(id - 1).copied().unwrap_or(std::ptr::null_mut())
    }

    /// Reverse: a field pointer → its stable handle.
    fn handle_of(st: &AppState, f: *mut pcapng_field_t) -> *mut c_void {
        match st.nodes.iter().position(|&p| p == f) {
            Some(i) => (i + 1) as *mut c_void,
            None => std::ptr::null_mut(),
        }
    }
}

impl TreeModel for DetailTree {
    fn child_count(&self, node: *mut c_void) -> i64 {
        let st = self.0.borrow();
        let parent = Self::resolve(&st, node);
        if parent.is_null() {
            return 0;
        }
        unsafe {
            let mut child = (*parent).children;
            let mut n = 0i64;
            while !child.is_null() {
                n += 1;
                child = (*child).next;
            }
            n
        }
    }

    fn child(&self, node: *mut c_void, index: i64) -> *mut c_void {
        let st = self.0.borrow();
        let parent = Self::resolve(&st, node);
        if parent.is_null() {
            return std::ptr::null_mut();
        }
        unsafe {
            let mut child = (*parent).children;
            let mut i = 0i64;
            while !child.is_null() {
                if i == index {
                    return Self::handle_of(&st, child);
                }
                i += 1;
                child = (*child).next;
            }
        }
        std::ptr::null_mut()
    }

    fn has_children(&self, node: *mut c_void) -> bool {
        let st = self.0.borrow();
        let f = Self::resolve(&st, node);
        !f.is_null() && unsafe { !(*f).children.is_null() }
    }

    fn label(&self, node: *mut c_void) -> String {
        let st = self.0.borrow();
        let f = Self::resolve(&st, node);
        if f.is_null() {
            return String::new();
        }
        unsafe {
            let ptr = (*f).label.as_ptr();
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

// ── run ──────────────────────────────────────────────────────────────────────

/// Open `cap` in the TUI. Returns an error (e.g. no TTY) rather than panicking.
pub fn run(cap: Capture) -> Result<(), String> {
    let ctx = Gtcaca::init().map_err(|e| {
        format!("cannot open terminal display: {e}. carscal's UI needs a real terminal; \
                 use `carscal --summary <file>` for headless output.")
    })?;

    let first_ts_us = cap.first_ts_us;
    let path = cap.path.clone();
    let total = cap.len();

    let state = Rc::new(RefCell::new(AppState {
        cap,
        rows: Vec::new(),
        sel: 0,
        dissection: None,
        nodes: Vec::new(),
        filter_text: String::new(),
        filter: Filter::compile("").unwrap(),
        first_ts_us,
        status: String::new(),
        colors: {
            let mut c = ColorRules::new();
            c.reload(crate::posa_dir::colorfilters_file().as_deref());
            c
        },
        extra_columns: Vec::new(),
        find_text: String::new(),
        find_needle: None,
        decode_text: String::new(),
        open_text: String::new(),
    }));
    state.borrow_mut().apply_filter();
    state.borrow_mut().refresh_selection();

    // Screen geometry from the application window.
    let app = gtcaca::Application::new(&ctx, "carscal");
    let win = gtcaca::Window::fullscreen(&app, None);
    let geo = win.geometry();
    let (w, h) = (geo.width.max(80), geo.height.max(24));

    // Row 0: the menu bar. Row 1: the display-filter box.
    let menus = build_menu();
    let menu = &menus.menu;
    // The filter/find/decode input line — an Entry so its text is visible and
    // updates as you type (a Label cannot change its text). Row 1, full width.
    let filter_entry = gtcaca::Entry::new(&win, 1, 1, win.content(NO_PAD).width);

    let table_top = 2;
    let table_h = (h - 3) / 2;
    let table = Table::new(
        &win,
        0,
        table_top,
        w,
        table_h,
        Box::new(PacketTable(Rc::clone(&state))),
    );
    let base_w: Vec<i32> = vec![6, 12, 16, 16, 7, 6, (w - 63).max(10)];
    set_widths(&table, &base_w, 0);
    table.set_title("Packets");

    let lower_top = table_top + table_h;
    let lower_h = h - lower_top - 1;
    let tree_w = w / 2;
    let tree = Tree::new(
        &win,
        0,
        lower_top,
        tree_w,
        lower_h,
        std::ptr::null_mut(),
        Box::new(DetailTree(Rc::clone(&state))),
    );
    tree.set_title("Packet details");

    let hex = Hexview::new(&win, tree_w + 1, lower_top, w - tree_w - 1, lower_h);
    hex.set_title("Bytes");

    // Give the focused pane a bright border/title so it's obvious which one is
    // active (gtcaca defaults focus and non-focus border colours to the same).
    let highlight_focus = |w: &dyn Widget| {
        let (_, fbg, nff, nfb) = w.colors();
        w.set_colors(caca::YELLOW, fbg, nff, nfb);
    };
    highlight_focus(&table);
    highlight_focus(&tree);
    highlight_focus(&hex);

    let statusbar = Statusbar::new("");

    let mut focus = Focus::Table;

    let sync_detail = |st: &AppState, tree: &Tree, hex: &Hexview| {
        // Rebuild the tree from the (now current) dissection — its root/child
        // counts are cached, so it must be reloaded on every selection change.
        tree.reload();
        if let Some(idx) = st.selected_pkt() {
            hex.set_data(&st.cap.pkts[idx].data);
        } else {
            hex.set_data(&[]);
        }
    };

    // Move selection to row `sel` and refresh the detail/hex panes.
    let goto = |sel: usize| {
        {
            let mut st = state.borrow_mut();
            st.sel = sel;
            st.refresh_selection();
        }
        table.set_current(sel as i64, 0);
        let st = state.borrow();
        sync_detail(&st, &tree, &hex);
    };

    // Search from the current selection using the stored needle.
    let search = |forward: bool| -> Option<usize> {
        let st = state.borrow();
        let needle = st.find_needle.as_ref()?;
        crate::find::find(&st.cap, st.sel, needle, forward)
    };

    // Initial paint.
    {
        let st = state.borrow();
        table.set_current(st.sel as i64, 0);
        sync_detail(&st, &tree, &hex);
    }

    loop {
        // Tell each pane whether it has focus, so the focused one shows its
        // cursor/highlight and takes navigation keys (like carcal's sync_focus).
        // While the menu bar is focused, no pane is, so the menu clearly owns it.
        set_pane_focus(focus, menu.is_focused(), &filter_entry, &table, &tree, &hex);
        ctx.redraw();
        table.draw();
        tree.draw();
        hex.draw();
        // Grey out capture-dependent items when no capture is loaded.
        menus.update(!state.borrow().cap.is_empty());
        menu.draw(); // the menu bar sits on top (row 0)
        {
            let st = state.borrow();
            let ftext = match focus {
                Focus::Filter => format!("Filter: {}_", st.filter_text),
                Focus::Find => format!("Find: {}_  (text or hex:DE AD BE EF)", st.find_text),
                Focus::DecodeAs => format!("Decode As: {}_", st.decode_text),
                Focus::OpenFile => format!("Open file: {}_", st.open_text),
                _ => format!("Filter: {}", st.filter_text),
            };
            filter_entry.set_text(&ftext);
            let shown = st.rows.len();
            let sel_no = st
                .selected_pkt()
                .map(|i| st.cap.pkts[i].number)
                .unwrap_or(0);
            statusbar.set_text(&format!(
                " {path}  |  {shown}/{total} shown  |  packet {sel_no}  |  {}",
                if st.status.is_empty() { focus_name(focus) } else { &st.status }
            ));
        }
        statusbar.draw();

        let k = match gtcaca::poll_key(-1) {
            Some(k) => k,
            None => continue,
        };

        const KEY_F2: i32 = 0x11b;
        const KEY_F9: i32 = 0x122;
        const KEY_F10: i32 = 0x123;
        const CTRL_O: i32 = 15;

        // The menu bar owns input while focused (F9/F10 to activate it).
        if menu.is_focused() {
            match k {
                key::TAB => {
                    menu.set_focus(false);
                    focus = next_focus(focus);
                }
                key::ESCAPE => menu.set_focus(false),
                _ => {
                    menu.handle_key(k);
                }
            }
            let a = take_pending();
            if a != 0 {
                menu.set_focus(false);
                match a {
                    act::QUIT => {
                        if confirm("Quit carscal", "Really quit carscal?") {
                            break;
                        }
                    }
                    act::OPEN => {
                        if let Some(p) = choose_file() {
                            match load_into(&state, &p) {
                                Ok(()) => goto(0),
                                Err(e) => state.borrow_mut().status = format!("open failed: {e}"),
                            }
                        }
                    }
                    act::CAPTURE_START => run_capture(&ctx, &app, &state, &menus, &table, &tree, &hex, &statusbar),
                    act::CAPTURE_STOP => {
                        state.borrow_mut().status = "not capturing".into();
                    }
                    act::FIND => focus = Focus::Find,
                    act::DECODE => focus = Focus::DecodeAs,
                    act::FIND_NEXT => {
                        if let Some(i) = search(true) {
                            goto(i);
                        }
                    }
                    act::FIND_PREV => {
                        if let Some(i) = search(false) {
                            goto(i);
                        }
                    }
                    act::MARK => {
                        let mut st = state.borrow_mut();
                        if let Some(idx) = st.selected_pkt() {
                            st.cap.pkts[idx].marked = !st.cap.pkts[idx].marked;
                        }
                    }
                    act::COLORIZE => {
                        let mut st = state.borrow_mut();
                        let on = !st.colors.is_enabled();
                        st.colors.set_enabled(on);
                        st.status = format!("colorize {}", if on { "on" } else { "off" });
                    }
                    act::CONV => {
                        apply_conv_filter(&state);
                        goto(0);
                        focus = Focus::Table;
                    }
                    act::APPLY_FILTER => {
                        if apply_as_filter(&state, &tree) {
                            goto(0);
                            focus = Focus::Table;
                        }
                    }
                    act::APPLY_COLUMN => {
                        if apply_as_column(&state, &tree) {
                            set_widths(&table, &base_w, state.borrow().extra_columns.len());
                        }
                    }
                    act::IOGRAPH => run_io_graph(&ctx, &app, &state),
                    act::FOLLOW => {
                        let lines = follow_lines(&state);
                        show_text_modal(&ctx, &app, "Follow Stream", &lines);
                    }
                    act::STATS_CONV => {
                        // Hosts ▸ Conversations tree + packet table. Enter on a
                        // packet jumps to it in the main list.
                        if let Some(row) = run_netflow(&ctx, &app, &state) {
                            goto(row);
                            focus = Focus::Table;
                        }
                    }
                    act::STATS_ENTITY => {
                        let model = {
                            let st = state.borrow();
                            crate::statstree::ArenaModel(std::rc::Rc::new(
                                crate::statstree::build_entity_explorer(&st.cap, &st.rows),
                            ))
                        };
                        run_tree_window(&ctx, &app, "Entity Explorer", "Connections", Box::new(model));
                    }
                    act::STATS_PROTO => {
                        let model = {
                            let st = state.borrow();
                            crate::statstree::ArenaModel(std::rc::Rc::new(
                                crate::statstree::build_proto_hierarchy(&st.cap),
                            ))
                        };
                        run_tree_window(
                            &ctx,
                            &app,
                            "Protocol Hierarchy Statistics",
                            "Protocol  (Right/Enter expand, Esc close)",
                            Box::new(model),
                        );
                    }
                    act::ABOUT => show_about(&ctx, &app),
                    act::SAVE => {
                        state.borrow_mut().status = "Save As: type a path via File ▸ Open flow (TODO)".into()
                    }
                    act::GOTO => {
                        if let Some(s) = prompt_line(&ctx, &app, "Go to Packet", "Packet number:") {
                            match s.trim().parse::<u64>() {
                                Ok(n) => {
                                    let row = {
                                        let st = state.borrow();
                                        st.rows.iter().position(|&i| st.cap.pkts[i].number == n)
                                    };
                                    match row {
                                        Some(r) => {
                                            goto(r);
                                            focus = Focus::Table;
                                        }
                                        None => state.borrow_mut().status = format!("no packet {n} in view"),
                                    }
                                }
                                Err(_) => state.borrow_mut().status = "not a packet number".into(),
                            }
                        }
                    }
                    act::RELOAD => {
                        let path = state.borrow().cap.path.clone();
                        if path.is_empty() || path.starts_with("live:") {
                            state.borrow_mut().status = "nothing to reload".into();
                        } else {
                            match load_into(&state, &path) {
                                Ok(()) => goto(0),
                                Err(e) => state.borrow_mut().status = format!("reload failed: {e}"),
                            }
                        }
                    }
                    act::UNMARK_ALL => {
                        let mut st = state.borrow_mut();
                        for p in st.cap.pkts.iter_mut() {
                            p.marked = false;
                        }
                        st.status = "all marks cleared".into();
                    }
                    act::RESET_COLUMNS => {
                        state.borrow_mut().extra_columns.clear();
                        set_widths(&table, &base_w, 0);
                        state.borrow_mut().status = "custom columns removed".into();
                    }
                    act::STATS_ENDPOINTS => {
                        let lines = endpoints_lines(&state.borrow().cap);
                        show_text_modal(&ctx, &app, "Endpoints", &lines);
                    }
                    act::COLOR_RULES => {
                        let lines = color_rules_lines(&state.borrow().colors);
                        show_text_modal(&ctx, &app, "Coloring Rules", &lines);
                    }
                    act::DECODERS => {
                        let mut lines = crate::decode::list_rules();
                        if lines.is_empty() {
                            lines.push("(no decode rules loaded)".into());
                        }
                        show_text_modal(&ctx, &app, "Decoders", &lines);
                    }
                    act::EXPORT_HTTP => export_objects(&ctx, &app, &state, libpcapng::ObjectProto::Http, "HTTP"),
                    act::EXPORT_SMB => export_objects(&ctx, &app, &state, libpcapng::ObjectProto::Smb, "SMB"),
                    _ => {}
                }
            }
            continue;
        }

        // F9 / F10 open the menu (F10 is grabbed by some terminals, so F9 too,
        // as Midnight Commander does). F2 / ^O open a file.
        if k == KEY_F9 || k == KEY_F10 {
            menu.set_focus(true);
            continue;
        }
        if (k == KEY_F2 || k == CTRL_O)
            && focus != Focus::Filter
            && focus != Focus::Find
            && focus != Focus::DecodeAs
        {
            if let Some(p) = choose_file() {
                match load_into(&state, &p) {
                    Ok(()) => goto(0),
                    Err(e) => state.borrow_mut().status = format!("open failed: {e}"),
                }
            }
            continue;
        }

        // Global keys first.
        const KEY_Q: i32 = b'q' as i32;
        const CTRL_Q: i32 = 17;
        const KEY_SLASH: i32 = b'/' as i32;
        const KEY_COLORIZE: i32 = b'C' as i32; // View ▸ Colorize toggle
        const KEY_DECODE: i32 = b'D' as i32; // Decode As…
        const KEY_IOGRAPH: i32 = b'I' as i32; // Statistics ▸ IO Graph
        const CTRL_F: i32 = 6; // Find
        match k {
            KEY_Q | CTRL_Q
                if focus != Focus::Filter
                    && focus != Focus::Find
                    && focus != Focus::DecodeAs
                    && focus != Focus::OpenFile =>
            {
                if confirm("Quit carscal", "Really quit carscal?") {
                    break;
                }
            }
            key::TAB => {
                focus = next_focus(focus);
                continue;
            }
            KEY_SLASH if focus != Focus::Filter && focus != Focus::Find => {
                focus = Focus::Filter;
                continue;
            }
            CTRL_F => {
                focus = Focus::Find;
                continue;
            }
            KEY_DECODE if focus != Focus::Filter && focus != Focus::Find && focus != Focus::DecodeAs => {
                focus = Focus::DecodeAs;
                continue;
            }
            KEY_IOGRAPH if focus != Focus::Filter && focus != Focus::Find && focus != Focus::DecodeAs => {
                run_io_graph(&ctx, &app, &state);
                continue;
            }
            KEY_COLORIZE if focus != Focus::Filter => {
                let mut st = state.borrow_mut();
                let on = !st.colors.is_enabled();
                st.colors.set_enabled(on);
                st.status = format!("colorize {}", if on { "on" } else { "off" });
                continue;
            }
            _ => {}
        }

        match focus {
            Focus::Filter => {
                let mut st = state.borrow_mut();
                match k {
                    key::RETURN => {
                        match Filter::compile(&st.filter_text) {
                            Ok(f) => {
                                st.filter = f;
                                st.status.clear();
                                st.apply_filter();
                                st.sel = 0;
                                st.refresh_selection();
                                drop(st);
                                let st = state.borrow();
                                table.set_current(0, 0);
                                sync_detail(&st, &tree, &hex);
                                focus = Focus::Table;
                            }
                            Err(e) => st.status = format!("bad filter: {e}"),
                        }
                    }
                    key::ESCAPE => {
                        focus = Focus::Table;
                    }
                    key::BACKSPACE | key::DELETE => {
                        st.filter_text.pop();
                    }
                    c if (0x20..0x7f).contains(&c) => {
                        st.filter_text.push(c as u8 as char);
                    }
                    _ => {}
                }
            }
            Focus::Find => {
                let mut act: Option<usize> = None;
                {
                    let mut st = state.borrow_mut();
                    match k {
                        key::RETURN => {
                            st.find_needle = crate::find::Needle::parse(&st.find_text);
                            if st.find_needle.is_none() {
                                st.status = "empty/invalid find".into();
                            }
                        }
                        key::ESCAPE => {
                            focus = Focus::Table;
                        }
                        key::BACKSPACE | key::DELETE => {
                            st.find_text.pop();
                        }
                        c if (0x20..0x7f).contains(&c) => {
                            st.find_text.push(c as u8 as char);
                        }
                        _ => {}
                    }
                }
                if k == key::RETURN {
                    if let Some(i) = search(true) {
                        act = Some(i);
                    } else {
                        state.borrow_mut().status = "not found".into();
                    }
                    focus = Focus::Table;
                }
                if let Some(i) = act {
                    goto(i);
                }
            }
            Focus::DecodeAs => {
                let mut apply = false;
                {
                    let mut st = state.borrow_mut();
                    match k {
                        key::RETURN => apply = true,
                        key::ESCAPE => focus = Focus::Table,
                        key::BACKSPACE | key::DELETE => {
                            st.decode_text.pop();
                        }
                        c if (0x20..0x7f).contains(&c) => st.decode_text.push(c as u8 as char),
                        _ => {}
                    }
                }
                if apply {
                    let spec = state.borrow().decode_text.clone();
                    // "cond => Decoder" is a conditional rule; otherwise a port spec.
                    let res = if spec.contains("=>") {
                        crate::decode::add_rule(&spec)
                    } else {
                        crate::decode::apply_spec(&spec)
                    };
                    {
                        let mut st = state.borrow_mut();
                        match res {
                            Ok(()) => {
                                // Decoding changed: drop cached summaries so the
                                // packet list re-dissects with the new rule.
                                for p in &mut st.cap.pkts {
                                    p.summary = None;
                                }
                                st.status = format!("decode-as: {spec}");
                                st.decode_text.clear();
                                st.apply_filter();
                            }
                            Err(e) => st.status = format!("decode-as error: {e}"),
                        }
                    }
                    let sel = state.borrow().sel;
                    goto(sel);
                    focus = Focus::Table;
                }
            }
            Focus::OpenFile => {
                let mut load: Option<String> = None;
                {
                    let mut st = state.borrow_mut();
                    match k {
                        key::RETURN => load = Some(st.open_text.trim().to_string()),
                        key::ESCAPE => focus = Focus::Table,
                        key::BACKSPACE | key::DELETE => {
                            st.open_text.pop();
                        }
                        c if (0x20..0x7f).contains(&c) => st.open_text.push(c as u8 as char),
                        _ => {}
                    }
                }
                if let Some(path) = load {
                    if path.is_empty() {
                        focus = Focus::Table;
                    } else {
                        match crate::source::load(&path) {
                            Ok(cap) => {
                                let mut st = state.borrow_mut();
                                st.first_ts_us = cap.first_ts_us;
                                st.cap = cap;
                                st.sel = 0;
                                st.open_text.clear();
                                st.status = format!("opened {path}");
                                st.apply_filter();
                                drop(st);
                                goto(0);
                                focus = Focus::Table;
                            }
                            Err(e) => state.borrow_mut().status = format!("open failed: {e}"),
                        }
                    }
                }
            }
            Focus::Table => {
                let moved = navigate_table(&state, k);
                if moved {
                    let mut st = state.borrow_mut();
                    st.refresh_selection();
                    let sel = st.sel;
                    drop(st);
                    table.set_current(sel as i64, 0);
                    let st = state.borrow();
                    sync_detail(&st, &tree, &hex);
                } else if k == b'm' as i32 {
                    let mut st = state.borrow_mut();
                    if let Some(idx) = st.selected_pkt() {
                        st.cap.pkts[idx].marked = !st.cap.pkts[idx].marked;
                    }
                } else if k == b'c' as i32 {
                    // Conversation Filter: filter to the selected packet's flow.
                    let mut st = state.borrow_mut();
                    if let Some(idx) = st.selected_pkt() {
                        if let Some(expr) = crate::stream::conversation_filter(&st.cap, idx) {
                            if let Ok(f) = Filter::compile(&expr) {
                                st.filter = f;
                                st.filter_text = expr;
                                st.sel = 0;
                                st.apply_filter();
                                st.refresh_selection();
                                drop(st);
                                table.set_current(0, 0);
                                let st = state.borrow();
                                sync_detail(&st, &tree, &hex);
                            }
                        }
                    }
                } else if k == b'n' as i32 {
                    if let Some(i) = search(true) {
                        goto(i);
                    }
                } else if k == b'N' as i32 {
                    if let Some(i) = search(false) {
                        goto(i);
                    }
                }
            }
            Focus::Tree if k == b'=' as i32 => {
                // Apply as Filter: filter on the selected field.
                let expr = {
                    let st = state.borrow();
                    let f = DetailTree::resolve(&st, tree.selected());
                    if f.is_null() {
                        None
                    } else {
                        dissect::field_filter_expr(&unsafe { Field::from_raw(f) })
                    }
                };
                if let Some(expr) = expr {
                    {
                        let mut st = state.borrow_mut();
                        if let Ok(f) = Filter::compile(&expr) {
                            st.filter = f;
                            st.filter_text = expr;
                            st.apply_filter();
                        }
                    }
                    goto(0);
                    focus = Focus::Table;
                }
            }
            Focus::Tree if k == b'|' as i32 => {
                // Apply as Column: add the selected field as a packet-list column.
                let mut st = state.borrow_mut();
                let f = DetailTree::resolve(&st, tree.selected());
                if !f.is_null() {
                    let abbrev = unsafe { Field::from_raw(f) }.abbrev().to_string();
                    if !abbrev.is_empty() && !st.extra_columns.contains(&abbrev) {
                        st.extra_columns.push(abbrev);
                        drop(st);
                        set_widths(&table, &base_w, state.borrow().extra_columns.len());
                    }
                }
            }
            Focus::Tree => {
                tree.key(k);
                // Highlight the selected field's bytes in the hex pane.
                let sel = tree.selected();
                let st = state.borrow();
                let f = DetailTree::resolve(&st, sel);
                if !f.is_null() {
                    unsafe {
                        let off = (*f).off.max(0);
                        let len = (*f).len.max(0);
                        hex.set_highlight(off, len);
                    }
                }
            }
            Focus::Hex => {
                hex.key(k);
                // Map the byte cursor to the deepest field covering it: highlight
                // that field's bytes and name it in the status bar (hex → field).
                if let Some(off) = hex.cursor() {
                    let st = state.borrow();
                    if let Some(d) = &st.dissection {
                        match unsafe { field_at_offset(d.root_ptr(), off) } {
                            Some(f) => unsafe {
                                let (fo, fl) = ((*f).off.max(0), (*f).len.max(0));
                                hex.set_highlight(fo, fl);
                                let label = std::ffi::CStr::from_ptr((*f).label.as_ptr())
                                    .to_string_lossy()
                                    .into_owned();
                                // Also unfold the detail tree to this field and
                                // select it, so hex ↔ tree stay in sync.
                                let handle = DetailTree::handle_of(&st, f);
                                drop(st);
                                if !handle.is_null() {
                                    tree.select(handle);
                                }
                                state.borrow_mut().status = format!("byte {off}: {label}");
                            },
                            None => hex.set_highlight(-1, 0),
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// The deepest field whose byte range `[off, off+len)` contains `offset`.
unsafe fn field_at_offset(
    node: *mut pcapng_field_t,
    offset: usize,
) -> Option<*mut pcapng_field_t> {
    if node.is_null() {
        return None;
    }
    let mut best: Option<*mut pcapng_field_t> = None;
    let mut child = (*node).children;
    while !child.is_null() {
        let (o, l) = ((*child).off.max(0) as usize, (*child).len.max(0) as usize);
        if l > 0 && offset >= o && offset < o + l {
            // Prefer the deepest (most specific) match.
            best = field_at_offset(child, offset).or(Some(child));
        } else if let Some(deep) = field_at_offset(child, offset) {
            best = Some(deep);
        }
        child = (*child).next;
    }
    best
}


// ── Statistics trees (Protocol Hierarchy, Conversations, Entity Explorer) ────

/// A generic expandable-tree modal (Protocol Hierarchy, Entity Explorer).
/// Right/Enter expand, Left collapse, ↑/↓ move, Esc/q close.
fn run_tree_window(
    ctx: &Gtcaca,
    app: &gtcaca::Application,
    title: &str,
    subtitle: &str,
    model: Box<dyn gtcaca::TreeModel>,
) {
    let win = gtcaca::Window::centered_fraction(app, Some(title), 0.85, 0.8);
    let c = win.content(PAD);
    let tree = Tree::new(&win, c.x, c.y, c.width, c.height, std::ptr::null_mut(), model);
    tree.set_title(subtitle);
    tree.set_focus(true);
    tree.key(key::RIGHT); // open the first row so there's something to see
    loop {
        ctx.redraw();
        tree.draw();
        match gtcaca::poll_key(-1) {
            Some(k) if k == key::ESCAPE || k == b'q' as i32 => break,
            Some(k) => {
                tree.key(k);
            }
            None => {}
        }
    }
    win.close();
}

/// The packet sub-table of the NetFlow window: the packets of the selected flow.
struct NfTable {
    state: Rc<RefCell<AppState>>,
    flow_rows: Rc<Vec<Vec<usize>>>,
    selflow: Rc<std::cell::Cell<i64>>,
}

impl TableModel for NfTable {
    fn row_count(&self) -> i64 {
        let f = self.selflow.get();
        if f < 0 {
            return 0;
        }
        self.flow_rows.get(f as usize).map(|r| r.len() as i64).unwrap_or(0)
    }
    fn headers(&self) -> Vec<String> {
        ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
    fn cell(&self, row: i64, col: i32) -> String {
        let f = self.selflow.get();
        if f < 0 {
            return String::new();
        }
        let Some(rows) = self.flow_rows.get(f as usize) else { return String::new() };
        let Some(&rr) = rows.get(row as usize) else { return String::new() };
        let mut st = self.state.borrow_mut();
        let Some(pidx) = st.rows.get(rr).copied() else { return String::new() };
        let first = st.first_ts_us;
        let s = dissect::summarize(&mut st.cap.pkts[pidx]);
        let pkt = &st.cap.pkts[pidx];
        match col {
            0 => pkt.number.to_string(),
            1 => format!("{:.6}", (pkt.ts_us.saturating_sub(first)) as f64 / 1_000_000.0),
            2 => s.src,
            3 => s.dst,
            4 => s.proto,
            5 => pkt.origlen.to_string(),
            _ => s.info,
        }
    }
}

/// Statistics ▸ Conversations (NetFlow): a Hosts ▸ Conversations tree on top and
/// a packet table (of the selected conversation) below. Tab switches panes;
/// Enter on a packet returns its row so the caller can jump to it in the main
/// list. Esc/q closes.
fn run_netflow(ctx: &Gtcaca, app: &gtcaca::Application, state: &Rc<RefCell<AppState>>) -> Option<usize> {
    let (arena, flow_rows) = {
        let st = state.borrow();
        crate::statstree::build_conversations(&st.cap, &st.rows)
    };
    let arena = Rc::new(arena);
    let flow_rows = Rc::new(flow_rows);
    if flow_rows.is_empty() {
        message("NetFlow", "No conversations found.");
        return None;
    }

    let win = gtcaca::Window::centered_fraction(app, Some("NetFlow \u{2014} Conversations"), 0.9, 0.85);
    let c = win.content(PAD);
    let tree_h = (c.height * 55 / 100).clamp(6, c.height - 6);
    let tree = Tree::new(
        &win,
        c.x,
        c.y,
        c.width,
        tree_h,
        std::ptr::null_mut(),
        Box::new(crate::statstree::ArenaModel(arena.clone())),
    );
    tree.set_title("Hosts \u{25b8} Conversations");
    let selflow = Rc::new(std::cell::Cell::new(-1i64));
    let table = Table::new(
        &win,
        c.x,
        c.y + tree_h + 1,
        c.width,
        (c.height - tree_h - 2).max(3),
        Box::new(NfTable { state: Rc::clone(state), flow_rows: Rc::clone(&flow_rows), selflow: Rc::clone(&selflow) }),
    );
    let _help = Label::new(&win, "\u{2191}\u{2193}/\u{2192} tree   Tab packets   Enter jump   Esc close", c.x, c.y + c.height - 1);

    // Point the table at the flow the tree has selected.
    let sync = |tree: &Tree, table: &Table| {
        selflow.set(arena.tag_of(tree.selected()));
        table.set_current(0, 0);
    };
    tree.key(key::RIGHT); // open the first host
    sync(&tree, &table);

    let mut on_tree = true;
    let mut jump: Option<usize> = None;
    loop {
        tree.set_focus(on_tree);
        table.set_focus(!on_tree);
        ctx.redraw();
        tree.draw();
        table.draw();
        match gtcaca::poll_key(-1) {
            Some(k) if k == key::ESCAPE || k == b'q' as i32 => break,
            Some(k) if k == key::TAB => on_tree = !on_tree,
            Some(k) if on_tree => {
                tree.key(k);
                sync(&tree, &table);
            }
            Some(k) if k == key::RETURN => {
                let f = selflow.get();
                if f >= 0 {
                    if let Some(rows) = flow_rows.get(f as usize) {
                        if let Some(&rr) = rows.get(table.current_row() as usize) {
                            jump = Some(rr);
                            break;
                        }
                    }
                }
            }
            Some(k) => {
                table.key(k);
            }
            None => {}
        }
    }
    win.close();
    jump
}

// ── IO Graph (Wireshark-style: multiple series, filters, colours, styles) ────

const IOG_INTERVALS: [f64; 6] = [0.001, 0.01, 0.1, 1.0, 10.0, 60.0];
const IOG_PALETTE: [u8; 8] = [
    caca::GREEN, caca::YELLOW, caca::LIGHTRED, caca::LIGHTCYAN,
    caca::LIGHTMAGENTA, caca::WHITE, caca::LIGHTBLUE, caca::BROWN,
];

/// A Y-axis mode. The `*Field` variants aggregate a chosen field's value per bin.
#[derive(Clone, Copy, PartialEq)]
enum YUnit {
    Packets,
    Bytes,
    Bits,
    Sum,
    CountFrames,
    CountFields,
    Max,
    Min,
    Avg,
}

impl YUnit {
    const ALL: [YUnit; 9] = [
        YUnit::Packets, YUnit::Bytes, YUnit::Bits, YUnit::Sum, YUnit::CountFrames,
        YUnit::CountFields, YUnit::Max, YUnit::Min, YUnit::Avg,
    ];
    fn next(self) -> YUnit {
        let i = Self::ALL.iter().position(|&u| u == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }
    fn is_field(self) -> bool {
        !matches!(self, YUnit::Packets | YUnit::Bytes | YUnit::Bits)
    }
    fn desc(self, field: &str) -> String {
        let f = if field.is_empty() { "?" } else { field };
        match self {
            YUnit::Packets => "Packets".into(),
            YUnit::Bytes => "Bytes".into(),
            YUnit::Bits => "Bits".into(),
            YUnit::Sum => format!("SUM({f})"),
            YUnit::CountFrames => format!("COUNT FRAMES({f})"),
            YUnit::CountFields => format!("COUNT FIELDS({f})"),
            YUnit::Max => format!("MAX({f})"),
            YUnit::Min => format!("MIN({f})"),
            YUnit::Avg => format!("AVG({f})"),
        }
    }
}

fn iog_color_name(c: u8) -> &'static str {
    match c {
        caca::GREEN => "Green",
        caca::YELLOW => "Yellow",
        caca::LIGHTRED => "Red",
        caca::LIGHTCYAN => "Cyan",
        caca::LIGHTMAGENTA => "Magenta",
        caca::WHITE => "White",
        caca::LIGHTBLUE => "Blue",
        caca::BROWN => "Orange",
        _ => "?",
    }
}
fn iog_style_name(s: i32) -> &'static str {
    ["Line", "Impulse", "Bar", "Dot"][(s & 3) as usize]
}

/// One graph line: a display filter, a colour/style, and a Y-axis mode.
struct IogSeries {
    enabled: bool,
    name: String,
    filter_text: String,
    filter: Option<Filter>, // None = match all
    color: u8,
    style: i32,
    yunit: YUnit,
    yfield: String,
}

/// `(#occurrences, #numeric, sum, min, max)` of `abbrev` in a dissection.
fn iog_field_stats(root: &libpcapng::Field, abbrev: &str) -> (usize, usize, f64, f64, f64) {
    fn walk(
        f: &libpcapng::Field,
        ab: &str,
        nf: &mut usize,
        nn: &mut usize,
        sum: &mut f64,
        lo: &mut f64,
        hi: &mut f64,
    ) {
        if f.abbrev() == ab {
            *nf += 1;
            if f.ftype() == libpcapng::FieldType::Uint {
                let v = f.uint() as f64;
                if *nn == 0 {
                    *lo = v;
                    *hi = v;
                } else {
                    if v < *lo {
                        *lo = v;
                    }
                    if v > *hi {
                        *hi = v;
                    }
                }
                *sum += v;
                *nn += 1;
            }
        }
        for c in f.children() {
            walk(&c, ab, nf, nn, sum, lo, hi);
        }
    }
    let (mut nf, mut nn, mut sum, mut lo, mut hi) = (0, 0, 0.0, 0.0, 0.0);
    walk(root, abbrev, &mut nf, &mut nn, &mut sum, &mut lo, &mut hi);
    (nf, nn, sum, lo, hi)
}

/// Bin every enabled series over the capture (one `Vec<f64>` of bins per series).
fn iog_bins(cap: &Capture, ser: &[IogSeries], t0: u64, span_us: u64, interval: f64) -> Vec<Vec<f64>> {
    let nb = (((span_us as f64) / (interval * 1e6)) as usize + 1).clamp(1, 4000);
    let mut acc = vec![vec![0.0f64; nb]; ser.len()];
    let mut cnt = vec![vec![0.0f64; nb]; ser.len()]; // sample counts (for AVG)
    // Only dissect when a series needs it (a filter or a field mode).
    let need = ser.iter().any(|g| g.enabled && (g.filter.is_some() || g.yunit.is_field()));
    for p in &cap.pkts {
        let b = ((p.ts_us.saturating_sub(t0) as f64) / (interval * 1e6)) as usize;
        let b = b.min(nb - 1);
        let d = if need { dissect::dissect(p) } else { None };
        for (s, g) in ser.iter().enumerate() {
            if !g.enabled {
                continue;
            }
            if let Some(f) = &g.filter {
                match &d {
                    Some(dd) if f.eval(&dd.root()) => {}
                    _ => continue,
                }
            }
            match g.yunit {
                YUnit::Packets => acc[s][b] += 1.0,
                YUnit::Bytes => acc[s][b] += p.origlen as f64,
                YUnit::Bits => acc[s][b] += p.origlen as f64 * 8.0,
                _ => {
                    let Some(dd) = &d else { continue };
                    if g.yfield.is_empty() {
                        continue;
                    }
                    let (nf, nn, sum, mn, mx) = iog_field_stats(&dd.root(), &g.yfield);
                    match g.yunit {
                        YUnit::CountFrames => {
                            if nf > 0 {
                                acc[s][b] += 1.0;
                            }
                        }
                        YUnit::CountFields => acc[s][b] += nf as f64,
                        _ if nn > 0 => match g.yunit {
                            YUnit::Sum => acc[s][b] += sum,
                            YUnit::Avg => {
                                acc[s][b] += sum;
                                cnt[s][b] += nn as f64;
                            }
                            YUnit::Max => {
                                if cnt[s][b] == 0.0 || mx > acc[s][b] {
                                    acc[s][b] = mx;
                                }
                                cnt[s][b] = 1.0;
                            }
                            YUnit::Min => {
                                if cnt[s][b] == 0.0 || mn < acc[s][b] {
                                    acc[s][b] = mn;
                                }
                                cnt[s][b] = 1.0;
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
    }
    for (s, g) in ser.iter().enumerate() {
        if g.yunit == YUnit::Avg {
            for i in 0..nb {
                if cnt[s][i] > 0.0 {
                    acc[s][i] /= cnt[s][i];
                }
            }
        }
    }
    acc
}

/// Statistics ▸ IO Graph: a Wireshark-style modal — up to 8 series, each with
/// its own display filter, colour, style and Y-axis mode; interval cycling and
/// a log Y axis. Keys are shown along the bottom. Blocks until Esc / Enter / q.
fn run_io_graph(ctx: &Gtcaca, app: &gtcaca::Application, state: &Rc<RefCell<AppState>>) {
    // Time span of the capture.
    let (t0, span_us, empty) = {
        let st = state.borrow();
        if st.cap.pkts.is_empty() {
            (0, 1, true)
        } else {
            let mut lo = st.cap.pkts[0].ts_us;
            let mut hi = lo;
            for p in &st.cap.pkts {
                lo = lo.min(p.ts_us);
                hi = hi.max(p.ts_us);
            }
            (lo, (hi.saturating_sub(lo)).max(1), false)
        }
    };
    if empty {
        message("IO Graph", "No capture loaded.");
        return;
    }

    // Default interval aiming for ~100 bins.
    let want = span_us as f64 / 1e6 / 100.0;
    let mut iv = IOG_INTERVALS
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| (**a - want).abs().total_cmp(&(**b - want).abs()))
        .map(|(i, _)| i)
        .unwrap_or(3);
    let mut log_y = false;

    // Default series: all packets, plus the active display filter (if any).
    let mut ser: Vec<IogSeries> = vec![IogSeries {
        enabled: true,
        name: "All packets".into(),
        filter_text: String::new(),
        filter: None,
        color: IOG_PALETTE[0],
        style: gtcaca::linechart::LINE,
        yunit: YUnit::Packets,
        yfield: String::new(),
    }];
    {
        let st = state.borrow();
        if !st.filter_text.is_empty() {
            if let Ok(f) = Filter::compile(&st.filter_text) {
                ser.push(IogSeries {
                    enabled: true,
                    name: "Filter".into(),
                    filter_text: st.filter_text.clone(),
                    filter: Some(f),
                    color: IOG_PALETTE[1],
                    style: gtcaca::linechart::IMPULSE,
                    yunit: YUnit::Packets,
                    yfield: String::new(),
                });
            }
        }
    }

    let ag = app.geometry();
    let w = (ag.width - 6).clamp(48, 130);
    let h = (ag.height - 4).max(16);
    let win = gtcaca::Window::centered(app, Some("IO Graph"), w, h);
    let c = win.content(PAD);
    let ch = (c.height * 55 / 100).clamp(6, (c.height - 6).max(6));
    let chart = gtcaca::Linechart::new(&win, c.x, c.y, c.width, ch);
    let _hdr = Label::new(
        &win,
        "    Graph          Color     Style     Y-Axis            Display filter",
        c.x,
        c.y + ch,
    );
    let tl = gtcaca::Textlist::new(&win, c.x, c.y + ch + 1);
    tl.set_view_size((c.height - ch - 3).max(1) as u32);
    tl.set_search_enabled(false); // '/' should not open search here
    let _help = Label::new(
        &win,
        "space on/off  f filter  F field  n name  c color  t style  y axis  i interval  L log  a add  d del  Esc",
        c.x,
        c.y + c.height - 1,
    );

    let mut sel = 0usize;

    // Recompute the chart + config list for the current series/interval.
    let refresh = |ser: &[IogSeries], sel: usize, iv: usize, log_y: bool| {
        let interval = IOG_INTERVALS[iv];
        let bins = {
            let st = state.borrow();
            iog_bins(&st.cap, ser, t0, span_us, interval)
        };
        chart.clear();
        chart.set_log_y(log_y);
        chart.set_xspan(span_us as f64 / 1e6, "s");
        chart.set_title(&format!(
            "IO Graph  \u{2014}  interval {interval} s{}",
            if log_y { "  log-Y" } else { "" }
        ));
        for (s, g) in ser.iter().enumerate() {
            if g.enabled {
                chart.add_series_styled(&bins[s], g.color, g.style, &g.name);
            }
        }
        tl.clear();
        for (s, g) in ser.iter().enumerate() {
            tl.append(&format!(
                "{} {} {:<13.13} {:<8} {:<8} {:<17.17} {}",
                if s == sel { ">" } else { " " },
                if g.enabled { "[x]" } else { "[ ]" },
                g.name,
                iog_color_name(g.color),
                iog_style_name(g.style),
                g.yunit.desc(&g.yfield),
                if g.filter_text.is_empty() { "(all packets)" } else { &g.filter_text },
            ));
        }
    };
    refresh(&ser, sel, iv, log_y);

    loop {
        ctx.redraw();
        chart.draw();
        tl.draw();
        let Some(k) = gtcaca::poll_key(-1) else { continue };
        let mut dirty = true;
        match k {
            key::ESCAPE | key::RETURN => break,
            _ if k == b'q' as i32 => break,
            key::UP => sel = sel.saturating_sub(1),
            key::DOWN => sel = (sel + 1).min(ser.len() - 1),
            _ if k == b' ' as i32 => ser[sel].enabled = !ser[sel].enabled,
            _ if k == b'c' as i32 => {
                let i = IOG_PALETTE.iter().position(|&p| p == ser[sel].color).unwrap_or(0);
                ser[sel].color = IOG_PALETTE[(i + 1) % IOG_PALETTE.len()];
            }
            _ if k == b't' as i32 => ser[sel].style = (ser[sel].style + 1) & 3,
            _ if k == b'y' as i32 => {
                ser[sel].yunit = ser[sel].yunit.next();
                if ser[sel].yunit.is_field() && ser[sel].yfield.is_empty() {
                    if let Some(f) = prompt_line(ctx, app, "IO Graph", "Y field (e.g. tcp.window_size):") {
                        if !f.trim().is_empty() {
                            ser[sel].yfield = f.trim().to_string();
                        }
                    }
                }
            }
            _ if k == b'F' as i32 => {
                if let Some(f) = prompt_line(ctx, app, "IO Graph", "Y field (e.g. tcp.window_size):") {
                    ser[sel].yfield = f.trim().to_string();
                }
            }
            _ if k == b'i' as i32 => iv = (iv + 1) % IOG_INTERVALS.len(),
            _ if k == b'L' as i32 => log_y = !log_y,
            _ if k == b'n' as i32 => {
                if let Some(n) = prompt_line(ctx, app, "IO Graph", "Graph name:") {
                    if !n.trim().is_empty() {
                        ser[sel].name = n.trim().to_string();
                    }
                }
            }
            _ if k == b'f' as i32 => {
                if let Some(fx) = prompt_line(ctx, app, "IO Graph", "Display filter (blank = all):") {
                    let fx = fx.trim().to_string();
                    if fx.is_empty() {
                        ser[sel].filter = None;
                        ser[sel].filter_text.clear();
                    } else {
                        match Filter::compile(&fx) {
                            Ok(f) => {
                                ser[sel].filter = Some(f);
                                ser[sel].filter_text = fx;
                            }
                            Err(e) => message("Filter error", &e),
                        }
                    }
                }
            }
            _ if k == b'a' as i32 => {
                if ser.len() < 8 {
                    let idx = ser.len();
                    ser.push(IogSeries {
                        enabled: true,
                        name: format!("Graph {}", idx + 1),
                        filter_text: String::new(),
                        filter: None,
                        color: IOG_PALETTE[idx % IOG_PALETTE.len()],
                        style: gtcaca::linechart::LINE,
                        yunit: YUnit::Packets,
                        yfield: String::new(),
                    });
                    sel = idx;
                }
            }
            _ if k == b'd' as i32 => {
                if ser.len() > 1 {
                    ser.remove(sel);
                    sel = sel.min(ser.len() - 1);
                }
            }
            _ => dirty = false,
        }
        if dirty {
            refresh(&ser, sel, iv, log_y);
        }
    }
    win.close();
}

/// A searchable interface picker (like carcal's). Returns the chosen interface
/// name, or `None` if cancelled. Type to filter the list; ↑/↓ select; Enter/Esc.
fn choose_interface(ctx: &Gtcaca, app: &gtcaca::Application) -> Option<String> {
    let devs = match libpcapng::list_devices() {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => {
            message("Capture", "No interfaces found (need root / CAP_NET_RAW).");
            return None;
        }
        Err(e) => {
            message("Capture", &format!("{e}"));
            return None;
        }
    };
    // Size the window to fit the interface list (like carcal). Child-widget
    // coordinates are RELATIVE to the window's top-left, not absolute.
    let ag = app.geometry();
    let n = devs.len() as i32;
    let w = 62.min(ag.width - 4).max(30);
    let h = (n + 6).clamp(10, ag.height - 2);
    let win = gtcaca::Window::centered(app, Some("Capture — choose interface (type to filter)"), w, h);
    let c = win.content(PAD);
    let tl = gtcaca::Textlist::new(&win, c.x, c.y);
    tl.set_view_size(c.height as u32);

    let mut search = String::new();
    let rebuild = |tl: &gtcaca::Textlist, search: &str| {
        tl.clear();
        let sl = search.to_lowercase();
        for d in &devs {
            if sl.is_empty()
                || d.name.to_lowercase().contains(&sl)
                || d.description.to_lowercase().contains(&sl)
            {
                let extra = if !d.description.is_empty() {
                    d.description.clone()
                } else if d.loopback {
                    "(loopback)".into()
                } else {
                    String::new()
                };
                tl.append(&format!("{:<16} {}", d.name, extra));
            }
        }
    };
    rebuild(&tl, &search);

    let chosen = loop {
        ctx.redraw();
        tl.draw();
        let k = match gtcaca::poll_key(-1) {
            Some(k) => k,
            None => continue,
        };
        match k {
            key::UP => tl.selection_up(),
            key::DOWN => tl.selection_down(),
            key::RETURN => {
                break tl.selected().and_then(|s| s.split_whitespace().next().map(String::from));
            }
            key::ESCAPE => break None,
            key::BACKSPACE | key::DELETE => {
                search.pop();
                rebuild(&tl, &search);
            }
            c if (0x20..0x7f).contains(&c) => {
                search.push(c as u8 as char);
                rebuild(&tl, &search);
            }
            _ => {}
        }
    };
    win.close();
    chosen
}

/// Live capture: pick an interface, then stream packets into the table using
/// libpcapng's non-blocking `dispatch` interleaved with key polling. The current
/// display filter is applied in-kernel too. Stops on q / Esc.
fn run_capture(
    ctx: &Gtcaca,
    app: &gtcaca::Application,
    state: &Rc<RefCell<AppState>>,
    menus: &Menus,
    table: &Table,
    tree: &Tree,
    hex: &Hexview,
    statusbar: &Statusbar,
) {
    let menu = &menus.menu;
    let dev = match choose_interface(ctx, app) {
        Some(d) => d,
        None => return,
    };
    // Prompt for an optional capture (BPF-level) filter, like carcal.
    let cfilter = match prompt_line(ctx, app, "Capture filter", "Capture filter (blank = all):") {
        Some(f) => f,
        None => return, // cancelled
    };

    let cap = match libpcapng::Capture::open(&dev) {
        Ok(c) => c,
        Err(e) => {
            message(
                "Capture — cannot open interface",
                &format!(
                    "Could not capture on {dev}:\n{e}\n\n\
                     Live capture needs elevated privileges:\n\
                     \u{2022} Linux:  run carscal with sudo, or grant CAP_NET_RAW\n\
                     \u{2022}         (sudo setcap cap_net_raw+eip $(which carscal))\n\
                     \u{2022} macOS:  run with sudo, or use Wireshark's ChmodBPF"
                ),
            );
            return;
        }
    };
    if !cfilter.trim().is_empty() {
        if let Err(e) = cap.set_filter(cfilter.trim()) {
            message("Capture filter error", &format!("{e}"));
            return;
        }
    }
    {
        let mut st = state.borrow_mut();
        st.cap = Capture { path: format!("live:{dev}"), ..Default::default() };
        st.rows.clear();
        st.sel = 0;
        st.status = format!("capturing on {dev} — press q or Esc to stop");
    }

    // The model-based widgets (table/tree/hex) must be drawn explicitly after
    // ctx.redraw() — that's how the main loop paints them, and the capture pump
    // has to do the same or new packets never appear.
    let repaint = || {
        ctx.redraw();
        table.draw();
        tree.draw();
        hex.draw();
    };
    // Rebuild the detail/hex for the current selection and repaint everything.
    let show_selection = || {
        let sel = state.borrow().sel;
        state.borrow_mut().refresh_selection();
        table.set_current(sel as i64, 0);
        // The tree caches its root/child counts — reload it from the new dissection.
        tree.reload();
        {
            let st = state.borrow();
            match st.selected_pkt() {
                Some(idx) => hex.set_data(&st.cap.pkts[idx].data),
                None => hex.set_data(&[]),
            }
        }
        repaint();
    };
    let status = |dev: &str, following: bool, pane: Focus| {
        let st = state.borrow();
        let (total, shown) = (st.cap.len(), st.rows.len());
        let mode = if following {
            "following newest"
        } else {
            match pane {
                Focus::Tree => "paused · details",
                Focus::Hex => "paused · bytes",
                _ => "paused · list",
            }
        };
        statusbar.set_text(&format!(
            " capturing on {dev}  |  {total} packets, {shown} shown  |  {mode}  |  Tab pane · ↑↓ move · f follow · q/Esc stop"
        ));
        statusbar.draw();
    };

    // During capture the user can move focus between the list, the detail tree,
    // and the bytes pane (Tab), so they can inspect a packet without stopping.
    let set_cap_focus = |pane: Focus| {
        table.set_focus(pane == Focus::Table);
        tree.set_focus(pane == Focus::Tree);
        hex.set_focus(pane == Focus::Hex);
    };
    let mut pane = Focus::Table;
    set_cap_focus(pane);

    // The menu bar stays reachable during capture (F9/F10). Reflect the running
    // capture in the Capture menu: Stop / Follow enabled, Start greyed.
    menus.update(true);
    menus.set_capturing(true);
    const KEY_F9: i32 = 0x122;
    const KEY_F10: i32 = 0x123;

    // `following`: keep the selection pinned to the newest packet until the user
    // navigates, at which point we pause auto-follow so they can inspect.
    let mut following = true;
    show_selection();
    status(&dev, following, pane);

    loop {
        let before = state.borrow().cap.len();
        let n = cap.dispatch(64, |p| {
            let mut st = state.borrow_mut();
            let ts_us = p.timestamp_ns / 1000;
            let idx = st.cap.push(crate::model::Packet::new(
                p.data.to_vec(),
                p.original_len,
                ts_us,
                crate::model::linktype::ETHERNET,
                0,
            ));
            let matches = st.filter.is_match_all()
                || dissect::dissect(&st.cap.pkts[idx])
                    .map(|d| st.filter.eval(&d.root()))
                    .unwrap_or(false);
            if matches {
                st.rows.push(idx);
            }
        });
        if n < 0 {
            if state.borrow().cap.is_empty() {
                // Failed before any packet — most likely a permission problem
                // (on Linux the socket is activated on the first dispatch).
                message(
                    "Capture — cannot start",
                    &format!(
                        "Could not capture on {dev} (permission denied?).\n\n\
                         Linux: run carscal with sudo, or grant CAP_NET_RAW.\n\
                         macOS: run with sudo, or use Wireshark's ChmodBPF."
                    ),
                );
            } else {
                message("Capture", &format!("capture on {dev} ended (device stopped delivering packets)."));
            }
            break;
        }
        let grew = state.borrow().cap.len() != before;
        if grew {
            if following {
                // Pin to and show the newest matching packet.
                let last = state.borrow().rows.len().saturating_sub(1);
                state.borrow_mut().sel = last;
                show_selection();
            } else {
                // Not following: only the row count changed; repaint the list.
                repaint();
            }
            status(&dev, following, pane);
        }
        // Non-blocking input poll; nap briefly when there was nothing to do.
        let key = gtcaca::poll_key(0);

        // The menu bar owns input while focused — reachable any time via F9/F10,
        // including mid-capture, so Stop / Follow Newest are always at hand.
        if menu.is_focused() {
            if let Some(k) = key {
                match k {
                    key::TAB | key::ESCAPE => menu.set_focus(false),
                    _ => {
                        menu.handle_key(k);
                    }
                }
                let a = take_pending();
                if a != 0 {
                    menu.set_focus(false);
                    match a {
                        act::CAPTURE_STOP => break,
                        act::CAPTURE_FOLLOW => {
                            following = true;
                            pane = Focus::Table;
                            set_cap_focus(pane);
                            let last = state.borrow().rows.len().saturating_sub(1);
                            state.borrow_mut().sel = last;
                            show_selection();
                        }
                        act::COLORIZE => {
                            let mut st = state.borrow_mut();
                            let on = !st.colors.is_enabled();
                            st.colors.set_enabled(on);
                        }
                        act::ABOUT => show_about(ctx, app),
                        // Other menu actions need a stopped capture; ignore them.
                        _ => {}
                    }
                }
                repaint();
                status(&dev, following, pane);
            } else if n == 0 {
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            continue;
        }

        match key {
            // F9/F10 open the menu bar without stopping the capture.
            Some(k) if k == KEY_F9 || k == KEY_F10 => {
                menu.set_focus(true);
                repaint();
            }
            Some(k) if k == b'q' as i32 || k == key::ESCAPE => break,
            // 'f' resumes following: back to the list, pinned to the newest packet.
            Some(k) if k == b'f' as i32 => {
                following = true;
                pane = Focus::Table;
                set_cap_focus(pane);
                let last = state.borrow().rows.len().saturating_sub(1);
                state.borrow_mut().sel = last;
                show_selection();
                status(&dev, following, pane);
            }
            // Tab cycles the focused pane (list → details → bytes). Leaving the
            // list pauses follow so the user can inspect the current packet.
            Some(k) if k == key::TAB => {
                pane = match pane {
                    Focus::Table => Focus::Tree,
                    Focus::Tree => Focus::Hex,
                    _ => Focus::Table,
                };
                if pane != Focus::Table {
                    following = false;
                }
                set_cap_focus(pane);
                repaint();
                status(&dev, following, pane);
            }
            Some(k) => match pane {
                // In the list: arrows move the selection (and pause follow).
                Focus::Table if is_nav_key(k) => {
                    following = false;
                    if navigate_table(state, k) {
                        show_selection();
                    }
                    status(&dev, following, pane);
                }
                // In the detail tree: fold/unfold and move within the packet.
                Focus::Tree => {
                    if tree.key(k) {
                        repaint();
                    }
                }
                // In the bytes pane: move the byte cursor, highlight the field it
                // covers, and select that field in the tree (same as the main UI).
                Focus::Hex => {
                    hex.key(k);
                    if let Some(off) = hex.cursor() {
                        let st = state.borrow();
                        if let Some(d) = &st.dissection {
                            match unsafe { field_at_offset(d.root_ptr(), off) } {
                                Some(f) => unsafe {
                                    hex.set_highlight((*f).off.max(0), (*f).len.max(0));
                                    let handle = DetailTree::handle_of(&st, f);
                                    drop(st);
                                    if !handle.is_null() {
                                        tree.select(handle);
                                    }
                                },
                                None => hex.set_highlight(-1, 0),
                            }
                        }
                    }
                    repaint();
                }
                _ => {}
            },
            None => {
                if n == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
            }
        }
    }
    // Leave capture mode: reset the Capture menu (Start enabled again) and make
    // sure the menu bar isn't left focused.
    menu.set_focus(false);
    menus.set_capturing(false);
    {
        let mut st = state.borrow_mut();
        let n = st.cap.len();
        st.status = format!("capture stopped ({n} packets)");
    }
    let sel = state.borrow().sel;
    goto_refresh(state, table, tree, hex, sel);
}

/// Set each pane's `has_focus` flag from the current [`Focus`], so the focused
/// widget draws its cursor/highlight and accepts navigation (gtcaca widgets gate
/// their selection rendering on this flag). Mirrors carcal's `sync_focus`.
fn set_pane_focus(
    focus: Focus,
    menu_focused: bool,
    filter: &gtcaca::Entry,
    table: &Table,
    tree: &Tree,
    hex: &Hexview,
) {
    // When the menu bar owns input, no content pane is focused.
    let on = |f: Focus| !menu_focused && focus == f;
    let is_input = !menu_focused
        && matches!(
            focus,
            Focus::Filter | Focus::Find | Focus::DecodeAs | Focus::OpenFile
        );
    filter.set_focus(is_input);
    table.set_focus(on(Focus::Table));
    tree.set_focus(on(Focus::Tree));
    hex.set_focus(on(Focus::Hex));
}

/// Whether a key is a packet-list navigation key.
fn is_nav_key(k: i32) -> bool {
    matches!(
        k,
        key::UP | key::DOWN | key::PAGE_UP | key::PAGE_DOWN | key::HOME | key::END
    )
}

/// A small centered prompt for a single line of text (uses an Entry so the typed
/// text is visible). Returns the entered string, or `None` if cancelled (Esc).
fn prompt_line(ctx: &Gtcaca, app: &gtcaca::Application, title: &str, label: &str) -> Option<String> {
    let win = gtcaca::Window::centered_fraction(app, Some(title), 0.5, 0.28);
    let c = win.content(PAD);
    let _l = Label::new(&win, label, c.x, c.y);
    let entry = gtcaca::Entry::new(&win, c.x, c.y + 1, c.width);
    let mut text = String::new();
    let result = loop {
        entry.set_text(&text);
        ctx.redraw();
        match gtcaca::poll_key(-1) {
            Some(k) if k == key::RETURN => break Some(text.clone()),
            Some(k) if k == key::ESCAPE => break None,
            Some(k) if k == key::BACKSPACE || k == key::DELETE => {
                text.pop();
            }
            Some(k) if (0x20..0x7f).contains(&k) => text.push(k as u8 as char),
            _ => {}
        }
    };
    win.close();
    result
}


/// A blocking single-OK message dialog.
fn message(title: &str, msg: &str) {
    let t = std::ffi::CString::new(title).unwrap_or_default();
    let m = std::ffi::CString::new(msg).unwrap_or_default();
    unsafe { gtcaca::ffi::gtcaca_dialog_message(t.as_ptr(), m.as_ptr()) };
}

/// Sync the table cursor + detail/hex to `sel` (shared by capture stop).
fn goto_refresh(
    state: &Rc<RefCell<AppState>>,
    table: &Table,
    tree: &Tree,
    hex: &Hexview,
    sel: usize,
) {
    {
        let mut st = state.borrow_mut();
        st.sel = sel;
        st.refresh_selection();
    }
    table.set_current(sel as i64, 0);
    let st = state.borrow();
    let _ = tree;
    if let Some(idx) = st.selected_pkt() {
        hex.set_data(&st.cap.pkts[idx].data);
    }
}

/// Run gtcaca's blocking file chooser; returns the chosen path, or `None`.
fn choose_file() -> Option<String> {
    let start = std::ffi::CString::new(".").unwrap();
    // c_char (not i8): char is unsigned on some targets, e.g. aarch64 Linux.
    let mut buf = [0 as std::os::raw::c_char; 1024];
    let ok = unsafe {
        gtcaca::ffi::gtcaca_filechooser_run(start.as_ptr(), buf.as_mut_ptr(), buf.len() as i32, 0)
    };
    if ok == 0 {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Blocking Yes/No confirmation dialog. Returns whether the user confirmed.
fn confirm(title: &str, message: &str) -> bool {
    let t = std::ffi::CString::new(title).unwrap_or_default();
    let m = std::ffi::CString::new(message).unwrap_or_default();
    unsafe { gtcaca::ffi::gtcaca_dialog_confirm(t.as_ptr(), m.as_ptr()) != 0 }
}

/// Load a capture into the shared state (used by File ▸ Open). Returns Ok status.
fn load_into(state: &Rc<RefCell<AppState>>, path: &str) -> Result<(), String> {
    let cap = crate::source::load(path)?;
    let mut st = state.borrow_mut();
    st.first_ts_us = cap.first_ts_us;
    st.cap = cap;
    st.sel = 0;
    st.status = format!("opened {path}");
    st.apply_filter();
    Ok(())
}

/// Set the filter to the selected packet's conversation.
fn apply_conv_filter(state: &Rc<RefCell<AppState>>) {
    let mut st = state.borrow_mut();
    if let Some(idx) = st.selected_pkt() {
        if let Some(expr) = crate::stream::conversation_filter(&st.cap, idx) {
            if let Ok(f) = Filter::compile(&expr) {
                st.filter = f;
                st.filter_text = expr;
                st.sel = 0;
                st.apply_filter();
            }
        }
    }
}

/// Apply the selected detail field as a display filter. Returns whether it did.
fn apply_as_filter(state: &Rc<RefCell<AppState>>, tree: &Tree) -> bool {
    let expr = {
        let st = state.borrow();
        let f = DetailTree::resolve(&st, tree.selected());
        if f.is_null() {
            None
        } else {
            dissect::field_filter_expr(&unsafe { Field::from_raw(f) })
        }
    };
    match expr {
        Some(expr) => {
            let mut st = state.borrow_mut();
            if let Ok(f) = Filter::compile(&expr) {
                st.filter = f;
                st.filter_text = expr;
                st.sel = 0;
                st.apply_filter();
            }
            true
        }
        None => false,
    }
}

/// Add the selected detail field as a packet-list column. Returns whether it did.
fn apply_as_column(state: &Rc<RefCell<AppState>>, tree: &Tree) -> bool {
    let mut st = state.borrow_mut();
    let f = DetailTree::resolve(&st, tree.selected());
    if f.is_null() {
        return false;
    }
    let abbrev = unsafe { Field::from_raw(f) }.abbrev().to_string();
    if !abbrev.is_empty() && !st.extra_columns.contains(&abbrev) {
        st.extra_columns.push(abbrev);
        true
    } else {
        false
    }
}

/// Reassembled-stream text for the selected packet's conversation.
fn follow_lines(state: &Rc<RefCell<AppState>>) -> Vec<String> {
    let st = state.borrow();
    let idx = match st.selected_pkt() {
        Some(i) => i,
        None => return vec!["No packet selected.".into()],
    };
    match crate::stream::follow(&st.cap, idx) {
        Some(f) => {
            let proto = if f.proto == 6 { "TCP" } else { "UDP" };
            let mut out = vec![
                format!("Follow {proto}: {}:{} <-> {}:{}  ({} packets)", f.client.0, f.client.1, f.server.0, f.server.1, f.packets),
                format!("client->server {} bytes, server->client {} bytes", f.client_bytes.len(), f.server_bytes.len()),
                String::new(),
                "── client → server ──".into(),
            ];
            out.extend(render_lines(&f.client_bytes));
            out.push("── server → client ──".into());
            out.extend(render_lines(&f.server_bytes));
            out
        }
        None => vec!["Selected packet is not part of a TCP/UDP conversation.".into()],
    }
}

/// Bytes → printable lines (control bytes shown as '.').
fn render_lines(b: &[u8]) -> Vec<String> {
    let text: String = b
        .iter()
        .map(|&c| if (0x20..0x7f).contains(&c) || c == b'\n' { c as char } else if c == b'\r' { ' ' } else { '.' })
        .collect();
    text.lines().map(|l| l.to_string()).collect()
}


/// Statistics ▸ Endpoints: per host:port packet/byte totals.
fn endpoints_lines(cap: &Capture) -> Vec<String> {
    let eps = crate::stats::endpoints(cap);
    let mut out = vec![format!("{:<42} {:>8} {:>12}", "Endpoint", "Packets", "Bytes")];
    for (ep, p, b) in eps.iter().take(500) {
        out.push(format!("{ep:<42} {p:>8} {b:>12}"));
    }
    if eps.is_empty() {
        out.push("(no endpoints)".into());
    }
    out
}

/// View ▸ Coloring Rules: the active rules in priority order.
fn color_rules_lines(colors: &ColorRules) -> Vec<String> {
    let mut out = vec![format!(
        "colorize: {}",
        if colors.is_enabled() { "on" } else { "off" }
    )];
    let rules = colors.list();
    for (expr, fg, bg) in &rules {
        out.push(format!(
            "{:>11} on {:<11}  {}",
            crate::colorrules::color_name(*fg),
            crate::colorrules::color_name(*bg),
            expr
        ));
    }
    if rules.is_empty() {
        out.push("(no coloring rules)".into());
    }
    out
}

/// File ▸ Export … Objects: carve HTTP/SMB files from the loaded capture, save
/// them to a directory the user names, and show what was written.
fn export_objects(
    ctx: &Gtcaca,
    app: &gtcaca::Application,
    state: &Rc<RefCell<AppState>>,
    proto: libpcapng::ObjectProto,
    label: &str,
) {
    let objs = crate::objects::extract(&state.borrow().cap, proto);
    if objs.is_empty() {
        state.borrow_mut().status = format!("no {label} objects found");
        return;
    }
    let default = std::env::var("HOME")
        .map(|h| format!("{h}/carscal-{}-objects", label.to_lowercase()))
        .unwrap_or_else(|_| format!("carscal-{}-objects", label.to_lowercase()));
    let Some(input) = prompt_line(
        ctx,
        app,
        &format!("Export {label} Objects ({} found)", objs.len()),
        &format!("Save to dir [{default}]:"),
    ) else {
        return;
    };
    let dir = if input.trim().is_empty() { default } else { input.trim().to_string() };
    match crate::objects::save_all(&objs, std::path::Path::new(&dir)) {
        Ok(n) => {
            let mut lines = vec![format!("Saved {n} {label} object(s) to:"), dir, String::new()];
            for (i, o) in objs.iter().enumerate() {
                lines.push(format!(
                    "{:>10} bytes  {}{}",
                    o.data.len(),
                    crate::objects::safe_name(o, i),
                    if o.complete { "" } else { "  (partial)" }
                ));
            }
            show_text_modal(ctx, app, &format!("{label} Objects"), &lines);
        }
        Err(e) => state.borrow_mut().status = format!("export failed: {e}"),
    }
}

/// The credits shown to the right of the About photo, including the version.
fn about_lines() -> Vec<String> {
    vec![
        "carscal".into(),
        format!("version {}", env!("CARGO_PKG_VERSION")),
        String::new(),
        "a terminal packet analyzer".into(),
        "a tiny Wireshark for the TUI".into(),
        String::new(),
        "gtcaca + libpcapng + LuaJIT".into(),
        String::new(),
        "Press any key to close".into(),
    ]
}

/// The About window, carcal-style: the caracal photo on the left, the credits
/// (with the version) on the right. The image widget letterboxes the photo, so
/// we just hand it a box on the left.
fn show_about(ctx: &Gtcaca, app: &gtcaca::Application) {
    let g = app.geometry();
    let w = 62.min(g.width - 4).max(40);
    let h = 16.min(g.height - 4).max(11);
    let win = gtcaca::Window::centered(app, Some("About carscal"), w, h);
    let c = win.content(PAD);

    // Left ~40% for the photo, leaving room for the text column on the right.
    let img_w = (c.width * 2 / 5).clamp(12, (c.width - 24).max(12));
    let img = gtcaca::Image::new(&win, c.x, c.y, img_w, c.height);
    let has_img = crate::posa_dir::asset_file("about.png")
        .map(|p| img.load(&p))
        .unwrap_or(false);

    let lines = about_lines();
    let tx = c.x + img_w + 2;
    let ty = c.y + ((c.height - lines.len() as i32).max(0)) / 2; // vertically centred
    let _labels: Vec<Label> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| Label::new(&win, l, tx, ty + i as i32))
        .collect();
    loop {
        ctx.redraw();
        if has_img {
            img.draw();
        }
        match gtcaca::poll_key(-1) {
            Some(k) if k == key::ESCAPE || k == key::RETURN || k == b'q' as i32 => break,
            _ => {}
        }
    }
    win.close();
}

/// A read-only centered text modal. Blocks until Esc / Enter / q.
fn show_text_modal(ctx: &Gtcaca, app: &gtcaca::Application, title: &str, lines: &[String]) {
    let win = gtcaca::Window::centered_fraction(app, Some(title), 0.8, 0.75);
    let c = win.content(PAD);
    // Labels are children of the window and draw with the redraw; keep them
    // alive for the modal's lifetime.
    let _labels: Vec<Label> = lines
        .iter()
        .take(c.height as usize)
        .enumerate()
        .map(|(i, line)| {
            let s: String = line.chars().take(c.width as usize).collect();
            Label::new(&win, &s, c.x, c.y + i as i32)
        })
        .collect();
    loop {
        ctx.redraw();
        match gtcaca::poll_key(-1) {
            Some(k) if k == key::ESCAPE || k == key::RETURN || k == b'q' as i32 => break,
            _ => {}
        }
    }
    win.close();
}

/// Set the table's column widths: the base columns plus `n_extra` columns of a
/// fixed width for any Apply-as-Column fields.
fn set_widths(table: &Table, base: &[i32], n_extra: usize) {
    let mut w = base.to_vec();
    w.extend(std::iter::repeat(14).take(n_extra));
    table.set_column_widths(&w);
}

fn focus_name(f: Focus) -> &'static str {
    match f {
        Focus::Filter => "focus: filter",
        Focus::Find => "find (Enter=search, n/N=repeat, Esc=cancel)",
        Focus::DecodeAs => "decode as: '<tcp|udp> <port> <Proto>' or '<cond> => <Proto>'",
        Focus::OpenFile => "open file: type a path, Enter to load, Esc to cancel",
        Focus::Table => "F9 menu  / filter  ^F find  D decode  c conv  m mark  I graph  Tab pane",
        Focus::Tree => "focus: details (= filter, | column)",
        Focus::Hex => "focus: bytes",
    }
}

fn next_focus(f: Focus) -> Focus {
    match f {
        Focus::Filter => Focus::Table,
        Focus::Find => Focus::Table,
        Focus::DecodeAs => Focus::Table,
        Focus::OpenFile => Focus::Table,
        Focus::Table => Focus::Tree,
        Focus::Tree => Focus::Hex,
        Focus::Hex => Focus::Filter,
    }
}

/// Update the selection index for the packet table; returns whether it moved.
fn navigate_table(state: &Rc<RefCell<AppState>>, k: i32) -> bool {
    let mut st = state.borrow_mut();
    let n = st.rows.len();
    if n == 0 {
        return false;
    }
    let old = st.sel;
    let page = 10;
    st.sel = match k {
        key::UP => st.sel.saturating_sub(1),
        key::DOWN => (st.sel + 1).min(n - 1),
        key::PAGE_UP => st.sel.saturating_sub(page),
        key::PAGE_DOWN => (st.sel + page).min(n - 1),
        key::HOME => 0,
        key::END => n - 1,
        _ => st.sel,
    };
    st.sel != old
}


#[cfg(test)]
mod tests {
    use super::{iog_bins, IogSeries, YUnit};
    use crate::model::{Capture, Packet};

    #[test]
    fn iog_bins_counts_all_packets_across_bins() {
        let mut cap = Capture::default();
        for i in 0..10u64 {
            cap.push(Packet::new(vec![], 100, i * 1_000_000, 1, 0)); // 1s apart, 100 bytes
        }
        let ser = vec![IogSeries {
            enabled: true,
            name: "all".into(),
            filter_text: String::new(),
            filter: None,
            color: 2,
            style: 0,
            yunit: YUnit::Packets,
            yfield: String::new(),
        }];
        // span = 9s, 1s intervals -> 10 bins, one packet each.
        let bins = iog_bins(&cap, &ser, 0, 9_000_000, 1.0);
        assert_eq!(bins.len(), 1);
        assert_eq!(bins[0].iter().sum::<f64>(), 10.0);
        assert!(bins[0].iter().all(|&v| v == 1.0));

        // Bytes mode: 100 bytes per packet.
        let ser_bytes = vec![IogSeries { yunit: YUnit::Bytes, ..clone_series(&ser[0]) }];
        let bytes = iog_bins(&cap, &ser_bytes, 0, 9_000_000, 1.0);
        assert_eq!(bytes[0].iter().sum::<f64>(), 1000.0);
    }

    fn clone_series(s: &IogSeries) -> IogSeries {
        IogSeries {
            enabled: s.enabled,
            name: s.name.clone(),
            filter_text: s.filter_text.clone(),
            filter: None,
            color: s.color,
            style: s.style,
            yunit: s.yunit,
            yfield: s.yfield.clone(),
        }
    }
}
