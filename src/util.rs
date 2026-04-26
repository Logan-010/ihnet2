use arboard::Clipboard;

pub fn display_and_copy(message: String, copy: bool) {
    println!("{}", message);
    if copy {
        Clipboard::new()
            .expect("Failed to get system clipboard")
            .set_text(message)
            .expect("Failed to write to clipboard");
        println!("Copied to clipboard...");
    }
}
