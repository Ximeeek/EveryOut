use crate::dto::*;
use std::collections::BTreeMap;
use ts_rs::{Config, TypeVisitor, TS};
pub fn typescript() -> String {
    struct Types {
        cfg: Config,
        declarations: BTreeMap<String, String>,
    }
    impl TypeVisitor for Types {
        fn visit<T: TS + 'static + ?Sized>(&mut self) {
            let name = T::name(&self.cfg);
            if T::output_path().is_none() || self.declarations.contains_key(&name) {
                return;
            }
            self.declarations
                .insert(name, format!("export {}", T::decl(&self.cfg)));
            T::visit_dependencies(self);
        }
    }
    let mut types = Types {
        cfg: Config::default(),
        declarations: BTreeMap::new(),
    };
    types.visit::<Settings>();
    types.visit::<ScanDto>();
    types.visit::<SelectionRequest>();
    types.visit::<ExecuteRequest>();
    types.visit::<PlanDto>();
    types.visit::<WipeEvent>();
    types.visit::<ModeResult>();
    types.visit::<RunStarted>();
    let mut output =
        String::from("// Rust IPC definitions. Update with pnpm bindings:generate.\n\n");
    for declaration in types.declarations.into_values() {
        output.push_str(&declaration);
        output.push_str("\n\n");
    }
    output.trim_end().to_owned() + "\n"
}
