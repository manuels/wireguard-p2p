#[macro_export]
/// Convert a Future<U,E> to a Future<U,()> and report E to stdout
macro_rules! report_errors {
    ( $func:expr ) => {{
        let func = || $func;

        func().or_else(|e| {
            println!("error: {}", e);

            for e in e.iter().skip(1) {
                println!("caused by: {}", e);
            }

            if let Some(backtrace) = e.backtrace() {
                println!("backtrace: {:?}", backtrace);
            }

            ::futures::future::err(())
        })
    }}
}

