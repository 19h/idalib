//! Hexrays Decompiler API Demo
//!
//! This example demonstrates the comprehensive hexrays bindings, including:
//! - Decompiling functions to C-like pseudocode
//! - Walking the C-tree AST (expressions and statements)
//! - Accessing local variables
//! - Working with function call arguments
//! - Using microcode (when available)
//!
//! Usage: cargo run --release --example hexrays_demo -- /path/to/binary

use std::env;

use idalib::IDAError;
use idalib::decompiler::{self, CExpr, CInsn, ctype};
use idalib::func::FunctionFlags;
use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).expect("Usage: hexrays_demo <binary>");

    println!("Opening {}...", path);
    let idb = IDB::open(path)?;

    if !idb.decompiler_available() {
        println!("Hexrays decompiler is not available!");
        return Ok(());
    }

    println!("Decompiler available!");
    println!("Functions: {}\n", idb.function_count());

    // Process first 5 non-tail functions
    let mut processed = 0;
    for (_fid, func) in idb.functions() {
        if func.flags().contains(FunctionFlags::TAIL) {
            continue;
        }

        let addr = func.start_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));

        println!("{}", "=".repeat(60));
        println!("Function: {} @ 0x{:x}", name, addr);
        println!("{}", "=".repeat(60));

        match idb.decompile(&func) {
            Ok(cfunc) => {
                analyze_function(&cfunc);
            }
            Err(IDAError::HexRays(e)) => {
                println!("Decompilation failed: {:?} - {}", e.code(), e.reason());
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }

        processed += 1;
        if processed >= 3 {
            break;
        }
        println!();
    }

    Ok(())
}

fn analyze_function(cfunc: &idalib::decompiler::CFunction) {
    // Basic info
    println!("\n[Function Info]");
    println!("  Entry EA: 0x{:x}", cfunc.entry_ea());
    println!("  Maturity: {}", cfunc.maturity());
    println!("  Declaration: {}", cfunc.declaration());
    println!("  Type: {}", cfunc.type_str());

    // Local variables
    println!("\n[Local Variables] ({})", cfunc.lvars_count());
    for lvar in cfunc.lvars() {
        let loc = if lvar.is_stk_var() {
            format!("stack[0x{:x}]", lvar.stkoff())
        } else if lvar.is_reg_var() {
            format!("reg{}", lvar.reg())
        } else {
            "unknown".to_string()
        };

        let kind = if lvar.is_arg() {
            "arg"
        } else if lvar.is_result() {
            "ret"
        } else {
            "var"
        };

        println!(
            "  {} {} : {} (width={}, loc={}, used={})",
            kind,
            lvar.name(),
            lvar.type_str(),
            lvar.width(),
            loc,
            lvar.is_used()
        );
    }

    // Function arguments
    println!("\n[Arguments] ({})", cfunc.args_count());
    for i in 0..cfunc.args_count() {
        if let Some(idx) = cfunc.arg_lvar_idx(i) {
            println!("  arg{}: lvar index {}", i, idx);
        }
    }

    // Warnings
    if cfunc.warnings_count() > 0 {
        println!("\n[Warnings] ({})", cfunc.warnings_count());
        for (ea, msg) in cfunc.warnings() {
            println!("  0x{:x}: {}", ea, msg);
        }
    }

    // AST analysis
    println!("\n[C-Tree Body]");
    let body = cfunc.body();
    println!("  {} top-level statements", body.len());

    // Walk the AST
    for (i, insn) in body.iter().enumerate().take(5) {
        println!(
            "\n  Statement #{}: {} (@ 0x{:x})",
            i,
            insn.op_name(),
            insn.ea()
        );
        analyze_statement(&insn, 2);
    }

    if body.len() > 5 {
        println!("\n  ... and {} more statements", body.len() - 5);
    }

    // Pseudocode output
    println!("\n[Pseudocode]");
    println!("{}", cfunc.pseudocode());

    // Microcode (if available)
    if let Some(mba) = cfunc.mba() {
        println!("\n[Microcode]");
        println!("  Entry: 0x{:x}", mba.entry_ea());
        println!("  Maturity: {}", mba.maturity());
        println!("  Blocks: {}", mba.qty());

        for block in mba.blocks().take(3) {
            println!(
                "\n  Block #{}: 0x{:x}-0x{:x} (type={})",
                block.serial(),
                block.start(),
                block.end(),
                block.block_type()
            );
            println!("    Predecessors: {}", block.npred());
            println!("    Successors: {}", block.nsucc());

            let insn_count: usize = block.instructions().count();
            println!("    Instructions: {}", insn_count);

            // Show first few instructions
            for (j, minsn) in block.instructions().enumerate().take(3) {
                println!("      {}: {} (0x{:x})", j, minsn.opcode_name(), minsn.ea());
            }
            if insn_count > 3 {
                println!("      ... and {} more", insn_count - 3);
            }
        }
    } else {
        println!("\n[Microcode] Not available (already optimized away)");
    }
}

fn analyze_statement(insn: &CInsn, indent: usize) {
    let prefix = "  ".repeat(indent);
    let op = insn.op();

    // Handle different statement types
    if op == ctype::cit_block() {
        if let Some(block) = insn.cblock() {
            println!("{}Block with {} statements", prefix, block.len());
            for child in block.iter().take(3) {
                analyze_statement(&child, indent + 1);
            }
        }
    } else if op == ctype::cit_expr() {
        if let Some(expr) = insn.cexpr() {
            print!("{}Expression: ", prefix);
            analyze_expression(&expr);
        }
    } else if op == ctype::cit_if() {
        println!("{}If statement:", prefix);
        if let Some(cond) = insn.if_cond() {
            print!("{}  condition: ", prefix);
            analyze_expression(&cond);
        }
        if let Some(then_branch) = insn.if_then() {
            println!("{}  then:", prefix);
            analyze_statement(&then_branch, indent + 2);
        }
        if let Some(else_branch) = insn.if_else() {
            println!("{}  else:", prefix);
            analyze_statement(&else_branch, indent + 2);
        }
    } else if op == ctype::cit_for() {
        println!("{}For loop:", prefix);
        if let Some(init) = insn.for_init() {
            print!("{}  init: ", prefix);
            analyze_expression(&init);
        }
        if let Some(cond) = insn.for_cond() {
            print!("{}  cond: ", prefix);
            analyze_expression(&cond);
        }
        if let Some(step) = insn.for_step() {
            print!("{}  step: ", prefix);
            analyze_expression(&step);
        }
    } else if op == ctype::cit_while() {
        println!("{}While loop:", prefix);
        if let Some(cond) = insn.while_cond() {
            print!("{}  cond: ", prefix);
            analyze_expression(&cond);
        }
    } else if op == ctype::cit_do() {
        println!("{}Do-while loop:", prefix);
        if let Some(cond) = insn.do_cond() {
            print!("{}  cond: ", prefix);
            analyze_expression(&cond);
        }
    } else if op == ctype::cit_return() {
        print!("{}Return: ", prefix);
        if let Some(expr) = insn.return_expr() {
            analyze_expression(&expr);
        } else {
            println!("(void)");
        }
    } else if op == ctype::cit_switch() {
        if let Some(expr) = insn.switch_expr() {
            print!("{}Switch on: ", prefix);
            analyze_expression(&expr);
        }
        println!("{}  {} cases", prefix, insn.switch_cases_count());
    } else if op == ctype::cit_goto() {
        println!("{}Goto label {}", prefix, insn.goto_label());
    } else if op == ctype::cit_break() {
        println!("{}Break", prefix);
    } else if op == ctype::cit_continue() {
        println!("{}Continue", prefix);
    } else {
        println!("{}{}", prefix, insn.op_name());
    }
}

fn analyze_expression(expr: &CExpr) {
    let op = expr.op();

    if op == ctype::cot_num() {
        println!("number: {} (type: {})", expr.numval(), expr.type_str());
    } else if op == ctype::cot_var() {
        println!("var[{}] (type: {})", expr.var_idx(), expr.type_str());
    } else if op == ctype::cot_obj() {
        println!("obj @ 0x{:x} (type: {})", expr.obj_ea(), expr.type_str());
    } else if op == ctype::cot_str() {
        println!("string: {:?}", expr.string());
    } else if op == ctype::cot_call() {
        print!("call");
        if let Some(target) = expr.x() {
            if target.op() == ctype::cot_obj() {
                print!(" @ 0x{:x}", target.obj_ea());
            } else if target.op() == ctype::cot_helper() {
                print!(" {}", target.helper());
            }
        }
        if let Some(args) = expr.call_args() {
            print!(" with {} args", args.len());
            for (i, arg) in args.iter().enumerate().take(3) {
                let a = arg.as_expr();
                print!(" [{}:{} ", i, a.op_name());
                if a.op() == ctype::cot_num() {
                    print!("{}", a.numval());
                } else if a.op() == ctype::cot_var() {
                    print!("var{}", a.var_idx());
                }
                print!("]");
            }
        }
        println!(" -> {}", expr.type_str());
    } else if op == ctype::cot_asg() {
        print!("assignment: ");
        if let Some(lhs) = expr.x() {
            print!("{}", lhs.op_name());
        }
        print!(" = ");
        if let Some(rhs) = expr.y() {
            print!("{}", rhs.op_name());
        }
        println!();
    } else if decompiler::is_binary_op(op) {
        print!("{}: ", expr.op_name());
        if let Some(x) = expr.x() {
            print!("{}", x.op_name());
        }
        print!(" <op> ");
        if let Some(y) = expr.y() {
            print!("{}", y.op_name());
        }
        println!(" -> {}", expr.type_str());
    } else if decompiler::is_unary_op(op) {
        print!("{}: ", expr.op_name());
        if let Some(x) = expr.x() {
            print!("{}", x.op_name());
        }
        println!(" -> {}", expr.type_str());
    } else {
        println!("{} (type: {})", expr.op_name(), expr.type_str());
    }
}
