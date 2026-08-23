#![no_std]

#[no_mangle]
pub extern "C" fn run(input: i32) -> i32 {
    input.wrapping_mul(2)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
