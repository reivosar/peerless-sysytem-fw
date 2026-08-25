//! Capability-free Wasmtime executor for an exported `run: (i32) -> i32`.

use thiserror::Error;
use wasmtime::{
    component, Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use crate::DEFAULT_TASK_MEMORY_LIMIT;

const DEFAULT_TASK_FUEL: u64 = 10_000_000;

#[derive(Debug, Error)]
pub enum WasmError {
    #[error("invalid WebAssembly component: {0}")]
    Invalid(String),
    #[error("requested export was not found or has the wrong type: {0}")]
    MissingExport(String),
    #[error("execution trapped: {0}")]
    Trap(String),
}

enum Compiled {
    Component(component::Component),
    Module(Module),
}

pub struct PureI32Module {
    engine: Engine,
    compiled: Compiled,
}

/// Capability-free byte buffer ABI for bulk jobs such as image processing.
/// Modules export `memory` and `run(ptr: i32, len: i32) -> i64`; the return
/// value packs output pointer in the high 32 bits and length in the low 32.
pub struct PureBytesModule {
    engine: Engine,
    module: Module,
}

impl PureBytesModule {
    pub fn parse(bytes: &[u8]) -> Result<Self, WasmError> {
        let engine = limited_engine()?;
        let module =
            Module::new(&engine, bytes).map_err(|error| WasmError::Invalid(error.to_string()))?;
        Ok(Self { engine, module })
    }
    pub fn invoke(&self, export: &str, input: &[u8]) -> Result<Vec<u8>, WasmError> {
        self.invoke_with_limit(export, input, DEFAULT_TASK_MEMORY_LIMIT)
    }
    pub fn invoke_with_limit(
        &self,
        export: &str,
        input: &[u8],
        memory_limit: u64,
    ) -> Result<Vec<u8>, WasmError> {
        let memory_limit = usize::try_from(memory_limit)
            .map_err(|_| WasmError::Invalid("memory limit exceeds host address space".into()))?;
        if input.len() > memory_limit {
            return Err(WasmError::Invalid(
                "input exceeds the task memory limit".into(),
            ));
        }
        let mut store = limited_store(&self.engine, memory_limit)?;
        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|error| WasmError::Trap(error.to_string()))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| WasmError::MissingExport("memory".into()))?;
        memory
            .write(&mut store, 0, input)
            .map_err(|error| WasmError::Trap(error.to_string()))?;
        let function = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, export)
            .map_err(|error| WasmError::MissingExport(error.to_string()))?;
        let packed = function
            .call(
                &mut store,
                (
                    0,
                    i32::try_from(input.len())
                        .map_err(|_| WasmError::Invalid("input exceeds i32 ABI".into()))?,
                ),
            )
            .map_err(|error| WasmError::Trap(error.to_string()))? as u64;
        let offset = (packed >> 32) as usize;
        let length = (packed & u32::MAX as u64) as usize;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| WasmError::Trap("output range overflow".into()))?;
        memory
            .data(&store)
            .get(offset..end)
            .map(ToOwned::to_owned)
            .ok_or_else(|| WasmError::Trap("output range is outside exported memory".into()))
    }
}

impl PureI32Module {
    pub fn parse(bytes: &[u8]) -> Result<Self, WasmError> {
        let engine = limited_engine()?;
        if let Ok(value) = component::Component::new(&engine, bytes) {
            return Ok(Self {
                engine,
                compiled: Compiled::Component(value),
            });
        }
        let module =
            Module::new(&engine, bytes).map_err(|error| WasmError::Invalid(error.to_string()))?;
        Ok(Self {
            engine,
            compiled: Compiled::Module(module),
        })
    }

    pub fn invoke(&self, export: &str, input: i32) -> Result<i32, WasmError> {
        self.invoke_with_limit(export, input, DEFAULT_TASK_MEMORY_LIMIT)
    }
    pub fn invoke_with_limit(
        &self,
        export: &str,
        input: i32,
        memory_limit: u64,
    ) -> Result<i32, WasmError> {
        let memory_limit = usize::try_from(memory_limit)
            .map_err(|_| WasmError::Invalid("memory limit exceeds host address space".into()))?;
        match &self.compiled {
            Compiled::Component(compiled) => {
                let mut store = limited_store(&self.engine, memory_limit)?;
                let linker = component::Linker::new(&self.engine);
                let instance = linker
                    .instantiate(&mut store, compiled)
                    .map_err(|error| WasmError::Trap(error.to_string()))?;
                let function = instance
                    .get_typed_func::<(i32,), (i32,)>(&mut store, export)
                    .map_err(|error| WasmError::MissingExport(error.to_string()))?;
                let (output,) = function
                    .call(&mut store, (input,))
                    .map_err(|error| WasmError::Trap(error.to_string()))?;
                Ok(output)
            }
            Compiled::Module(compiled) => {
                let mut store = limited_store(&self.engine, memory_limit)?;
                let instance = Instance::new(&mut store, compiled, &[])
                    .map_err(|error| WasmError::Trap(error.to_string()))?;
                instance
                    .get_typed_func::<i32, i32>(&mut store, export)
                    .map_err(|error| WasmError::MissingExport(error.to_string()))?
                    .call(&mut store, input)
                    .map_err(|error| WasmError::Trap(error.to_string()))
            }
        }
    }
}

fn limited_engine() -> Result<Engine, WasmError> {
    let mut config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config).map_err(|error| WasmError::Invalid(error.to_string()))
}

fn limited_store(engine: &Engine, memory_limit: usize) -> Result<Store<StoreLimits>, WasmError> {
    let limits = StoreLimitsBuilder::new().memory_size(memory_limit).build();
    let mut store = Store::new(engine, limits);
    store.limiter(|limits| limits);
    store
        .set_fuel(DEFAULT_TASK_FUEL)
        .map_err(|error| WasmError::Invalid(error.to_string()))?;
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    const DOUBLE: &[u8] = b"\0asm\x01\0\0\0\x01\x06\x01\x60\x01\x7f\x01\x7f\x03\x02\x01\x00\x07\x07\x01\x03run\x00\x00\x0a\x09\x01\x07\x00\x20\x00\x41\x02\x6c\x0b";
    #[test]
    fn executes_pure_wasm_with_wasmtime() {
        assert_eq!(
            PureI32Module::parse(DOUBLE)
                .unwrap()
                .invoke("run", 21)
                .unwrap(),
            42
        );
    }
    #[test]
    fn rejects_non_wasm() {
        assert!(PureI32Module::parse(b"native").is_err());
    }

    #[test]
    fn linear_memory_cannot_grow_past_the_task_limit() {
        let bytes = wat::parse_str(
            r#"
            (module
                (memory 1)
                (func (export "run") (param i32) (result i32)
                    i32.const 1
                    memory.grow
                    drop
                    memory.size))
            "#,
        )
        .unwrap();
        let module = PureI32Module::parse(&bytes).unwrap();
        assert_eq!(module.invoke_with_limit("run", 0, 64 * 1024).unwrap(), 1);
        assert_eq!(module.invoke_with_limit("run", 0, 128 * 1024).unwrap(), 2);
    }

    #[test]
    fn byte_input_larger_than_the_task_limit_is_rejected_before_instantiation() {
        let bytes = wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (func (export "run") (param i32 i32) (result i64)
                    i64.const 0))
            "#,
        )
        .unwrap();
        let error = PureBytesModule::parse(&bytes)
            .unwrap()
            .invoke_with_limit("run", &[0; 65], 64)
            .unwrap_err();
        assert!(error.to_string().contains("input exceeds"));
    }

    #[test]
    fn infinite_loop_is_stopped_by_fuel_limit() {
        let bytes = wat::parse_str(
            r#"
            (module
                (func (export "run") (param i32) (result i32)
                    (loop $forever
                        br $forever)
                    i32.const 0))
            "#,
        )
        .unwrap();
        let error = PureI32Module::parse(&bytes)
            .unwrap()
            .invoke("run", 0)
            .unwrap_err();
        assert!(matches!(error, WasmError::Trap(_)));
    }

    #[test]
    fn executes_a_component_model_component() {
        let bytes = wat::parse_str(
            r#"
            (component
                (core module $module
                    (func (export "run") (param i32) (result i32)
                        local.get 0 i32.const 2 i32.mul))
                (core instance $instance (instantiate $module))
                (func (export "run") (param "input" s32) (result s32)
                    (canon lift (core func $instance "run"))))
        "#,
        )
        .unwrap();
        assert_eq!(
            PureI32Module::parse(&bytes)
                .unwrap()
                .invoke("run", 21)
                .unwrap(),
            42
        );
    }

    #[test]
    fn rejects_modules_that_request_host_capabilities() {
        let bytes = wat::parse_str(
            r#"(module
                (import "host" "read_secret" (func $secret (result i32)))
                (func (export "run") (param i32) (result i32)
                    call $secret))"#,
        )
        .unwrap();
        let module = PureI32Module::parse(&bytes).unwrap();
        assert!(module.invoke("run", 1).is_err());
    }

    #[test]
    fn executes_byte_buffer_abi() {
        let bytes = wat::parse_str(
            r#"(module
            (memory (export "memory") 1)
            (func (export "run") (param i32 i32) (result i64)
              i32.const 16 i32.const 42 i32.store8
              i64.const 68719476737))"#,
        )
        .unwrap();
        assert_eq!(
            PureBytesModule::parse(&bytes)
                .unwrap()
                .invoke("run", b"in")
                .unwrap(),
            vec![42]
        );
    }

    #[test]
    fn byte_buffer_abi_rejects_output_outside_guest_memory() {
        let bytes = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "run") (param i32 i32) (result i64)
                  i64.const 281474976710657))"#,
        )
        .unwrap();
        assert!(PureBytesModule::parse(&bytes)
            .unwrap()
            .invoke("run", b"input")
            .is_err());
    }
}
