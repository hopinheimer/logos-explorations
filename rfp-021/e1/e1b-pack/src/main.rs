fn main() {
    let mut args = std::env::args().skip(1);
    let (elf, out) = (args.next().expect("user ELF"), args.next().expect("output path"));
    let user_elf = std::fs::read(&elf).expect("read user ELF");
    let bin = risc0_binfmt::ProgramBinary::new(&user_elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let id = risc0_zkvm::compute_image_id(&bin).expect("image id");
    std::fs::write(&out, &bin).expect("write program binary");
    println!("{out} bytes={} image_id={id}", bin.len());
}
