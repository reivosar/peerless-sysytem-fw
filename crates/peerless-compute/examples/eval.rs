use peerless_compute::wasm::PureI32Module;
use std::{env, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let module = fs::read(args.next().ok_or("usage: eval WASM INPUT")?)?;
    let input = args.next().ok_or("missing input")?.parse()?;
    println!("{}", PureI32Module::parse(&module)?.invoke("run", input)?);
    Ok(())
}
