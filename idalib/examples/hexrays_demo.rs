//! Hexrays Decompiler API Demo
//!
//! This example demonstrates the comprehensive hexrays bindings, including:
//! - Decompiling functions to C-like pseudocode
//! - Walking the C-tree AST (expressions and statements)
//! - Accessing and modifying local variables
//! - Working with function call arguments
//! - Using microcode (mba, mblock, minsn, mop)
//! - Tree navigation (find_parent_of, find_by_ea)
//! - Switch statements with case iteration
//! - Pseudocode line-by-line access
//! - Expression type introspection
//! - Decompiler event callbacks
//!
//! Usage: cargo run --release --example hexrays_demo -- /path/to/binary

use std::env;
use std::sync::atomic::{AtomicU32, Ordering};

use idalib::IDAError;
use idalib::decompiler::{
    self, CExpr, CInsn, ctype, funcrole, get_merror_desc, install_hexrays_callback, itp,
    mcode_is_call, mcode_is_comparison, mcode_is_jcc, mcode_is_jump, mcode_is_ret, mcode_name,
    merror, mop_type, negate_mcode_relation, remove_hexrays_callback, role_name,
};
use idalib::func::FunctionFlags;
use idalib::idb::IDB;

// Global counter for callback demo
static EVENT_COUNT: AtomicU32 = AtomicU32::new(0);

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

    // Install a callback to monitor decompilation events
    println!("[Installing Hexrays Callback]");
    let callback_installed = install_hexrays_callback(|data| {
        let count = EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
        // Only print first few events to avoid spam
        if count < 10 {
            println!(
                "  -> Event: {} (extra={}, mba={}, cfunc={})",
                data.event.name(),
                data.extra,
                data.has_mba,
                data.has_cfunc
            );
        }
        0 // Continue processing
    });
    println!("  Callback installed: {}\n", callback_installed);

    // Process first 3 non-tail functions
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

    // Remove the callback and show stats
    remove_hexrays_callback();
    let total_events = EVENT_COUNT.load(Ordering::Relaxed);
    println!("\n[Callback Summary]");
    println!("  Total events received: {}", total_events);

    Ok(())
}

fn analyze_function(cfunc: &idalib::decompiler::CFunction) {
    // Basic info
    println!("\n[Function Info]");
    println!("  Entry EA: 0x{:x}", cfunc.entry_ea());
    println!("  Maturity: {}", cfunc.maturity());
    println!("  Declaration: {}", cfunc.declaration());
    println!("  Type: {}", cfunc.type_str());

    // User annotations info
    println!("\n[User Annotations]");
    println!("  User comments: {}", cfunc.user_cmts_count());
    println!("  User labels: {}", cfunc.user_labels_count());
    println!("  Number formats: {}", cfunc.numforms_count());

    // Demo: User comment access (if any exist)
    if cfunc.user_cmts_count() > 0 {
        println!("  (User comments exist at various locations)");
    }

    // Show item preciser constants (itp)
    println!("\n[Item Preciser Constants (for comments)]");
    println!("  itp::semi() = {} (after semicolon)", itp::semi());
    println!("  itp::curly1() = {} (after {{)", itp::curly1());
    println!("  itp::for_arg(0) = {} (after arg 0)", itp::for_arg(0));

    // Show function role constants
    println!("\n[Function Role Constants]");
    println!(
        "  funcrole::memcpy() = {} ({})",
        funcrole::memcpy(),
        role_name(funcrole::memcpy())
    );
    println!(
        "  funcrole::strlen() = {} ({})",
        funcrole::strlen(),
        role_name(funcrole::strlen())
    );
    println!(
        "  funcrole::alloca() = {} ({})",
        funcrole::alloca(),
        role_name(funcrole::alloca())
    );

    // Local variables - show how to access by index and by name
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

    // Demo: lvar_at and find_lvar_by_name
    if cfunc.lvars_count() > 0 {
        println!("\n[Local Variable Access Demo]");
        if let Some(lvar) = cfunc.lvar_at(0) {
            println!("  lvar_at(0): {}", lvar.name());
            // Try to find by name
            let name = lvar.name();
            if let Some(found) = cfunc.find_lvar_by_name(&name) {
                println!("  find_lvar_by_name(\"{}\"): found!", found.name());
            }
        }
    }

    // Demo: Local variable modification APIs (read-only demo - shows available methods)
    println!("\n[Local Variable Modification APIs]");
    println!("  Available in-memory methods (not persistent):");
    println!("    lvar.set_name(name) - Rename variable");
    println!("    lvar.set_type(type_str) - Set type from C declaration");
    println!("    lvar.set_comment(cmt) - Set comment");
    println!("  Available persistent methods (saved to DB):");
    println!("    lvar.rename_persistent(name) - Rename and save to DB");
    println!("    lvar.set_type_persistent(type_str) - Set type and save to DB");
    println!("    lvar.set_comment_persistent(cmt) - Set comment and save to DB");
    println!("    lvar.set_noptr(bool) - Mark as non-pointer");
    println!("    lvar.set_nomap(bool) - Forbid automatic variable mapping");
    println!("    lvar.set_unused(bool) - Mark argument as unused");
    println!("    lvar.modify_persistent(name, type, cmt) - Modify multiple attributes");

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

    // Pseudocode line-by-line access
    println!("\n[Pseudocode Lines] ({})", cfunc.pseudocode_line_count());
    for i in 0..cfunc.pseudocode_line_count().min(5) {
        println!("  {}: {}", i, cfunc.pseudocode_line_at(i));
    }
    if cfunc.pseudocode_line_count() > 5 {
        println!("  ... and {} more lines", cfunc.pseudocode_line_count() - 5);
    }

    // Boundaries and eamap info
    println!("\n[Mapping Info]");
    println!("  Boundaries: {}", cfunc.boundaries_count());
    println!("  EAMap entries: {}", cfunc.eamap_count());

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

    // Demo: Tree navigation with find_by_ea
    println!("\n[Tree Navigation Demo]");
    let entry = cfunc.entry_ea();
    if let Some(item) = cfunc.find_by_ea(entry) {
        println!(
            "  find_by_ea(0x{:x}): found {} @ 0x{:x}",
            entry,
            item.op_name(),
            item.ea()
        );
        // Try to find its parent
        if let Some(parent) = cfunc.find_parent_of(&item) {
            println!("  parent: {} @ 0x{:x}", parent.op_name(), parent.ea());
        }
    }

    // Microcode (if available) - enhanced with new features
    if let Some(mba) = cfunc.mba() {
        println!("\n[Microcode]");
        println!("  Entry: 0x{:x}", mba.entry_ea());
        println!("  Maturity: {}", mba.maturity());
        println!(
            "  Final maturity (const): {}",
            idalib::decompiler::Mba::final_maturity()
        );
        println!("  Blocks: {}", mba.qty());
        println!("  Stack size: {}", mba.stack_size());
        println!("  Args count: {}", mba.args_count());
        println!("  Min EA: 0x{:x}", mba.min_ea());
        println!("  Is thunk: {}", mba.is_thunk());
        println!("  Flags: 0x{:x}", mba.flags());

        // New mba predicates
        println!("\n  [MBA Predicates]");
        println!("    has_calls: {}", mba.has_calls());
        println!("    is_pattern: {}", mba.is_pattern());
        println!("    returns_float: {}", mba.returns_float());
        println!("    has_glbopt: {}", mba.has_glbopt());
        println!("    is_cmnstk: {}", mba.is_cmnstk());

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
            println!("    Instruction count: {}", block.insn_count());
            println!("    Flags: 0x{:x}", block.flags());

            // New mblock predicates
            let block_preds = [
                ("is_call_block", block.is_call_block()),
                ("is_nway", block.is_nway()),
                ("is_branch", block.is_branch()),
                ("is_simple_goto_block", block.is_simple_goto_block()),
                ("is_simple_jcnd_block", block.is_simple_jcnd_block()),
                ("is_empty", block.is_empty()),
                ("is_noret", block.is_noret()),
            ];
            let active: Vec<_> = block_preds
                .iter()
                .filter(|(_, v)| *v)
                .map(|(n, _)| *n)
                .collect();
            if !active.is_empty() {
                println!("    Block props: {}", active.join(", "));
            }

            // Show first few instructions with detailed operand info
            for (j, minsn) in block.instructions().enumerate().take(3) {
                let opcode = minsn.opcode();

                // Categorize the instruction
                let mut cats = Vec::new();
                if mcode_is_comparison(opcode) {
                    cats.push("cmp".to_string());
                }
                if mcode_is_jcc(opcode) {
                    cats.push("jcc".to_string());
                    // Demo: negate the relation
                    let negated = negate_mcode_relation(opcode);
                    cats.push(format!("neg={}", mcode_name(negated)));
                }
                if mcode_is_call(opcode) {
                    cats.push("call".to_string());
                }
                if mcode_is_jump(opcode) {
                    cats.push("jmp".to_string());
                }
                if mcode_is_ret(opcode) {
                    cats.push("ret".to_string());
                }

                let cats_str = if cats.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", cats.join(", "))
                };

                println!(
                    "      {}: {} (0x{:x}){}",
                    j,
                    mcode_name(opcode),
                    minsn.ea(),
                    cats_str
                );

                // New minsn predicates
                let insn_preds = [
                    ("tailcall", minsn.is_tailcall()),
                    ("fpinsn", minsn.is_fpinsn()),
                    ("farcall", minsn.is_farcall()),
                    ("propagatable", minsn.is_propagatable()),
                ];
                let active: Vec<_> = insn_preds
                    .iter()
                    .filter(|(_, v)| *v)
                    .map(|(n, _)| *n)
                    .collect();
                if !active.is_empty() {
                    println!("        Props: {}", active.join(", "));
                }

                // Show operands using the new Mop wrapper
                if let Some(left) = minsn.left() {
                    print!("        L: type={}", left.op_type());
                    if left.is_reg() {
                        print!(" reg={}", left.reg().unwrap_or(-1));
                    } else if left.is_number() {
                        print!(" num={}", left.number_value().unwrap_or(0));
                    } else if left.is_stack() {
                        print!(" stkoff={}", left.stack_offset().unwrap_or(0));
                    } else if left.is_arglist() {
                        // Show call info for mop_f operands
                        print!(" call_args={}", left.call_args_count());
                        let role = left.call_role();
                        if role != funcrole::unk() {
                            print!(" role={}", role_name(role));
                        }
                        if left.call_is_vararg() {
                            print!(" (vararg)");
                        }
                        if left.call_is_noret() {
                            print!(" (noret)");
                        }
                    }
                    println!(" size={}", left.size());
                }
                if let Some(right) = minsn.right() {
                    print!("        R: type={}", right.op_type());
                    if right.is_reg() {
                        print!(" reg={}", right.reg().unwrap_or(-1));
                    } else if right.is_number() {
                        print!(" num={}", right.number_value().unwrap_or(0));
                    }
                    println!(" size={}", right.size());
                }
                if let Some(dest) = minsn.dest() {
                    println!("        D: type={} size={}", dest.op_type(), dest.size());
                }
            }
            let insn_count = block.insn_count();
            if insn_count > 3 {
                println!("      ... and {} more", insn_count - 3);
            }
        }

        // Show mop_type constants
        println!("\n  [Mop Type Constants]");
        println!("    mop_z (zero/none): {}", mop_type::z());
        println!("    mop_r (register): {}", mop_type::r());
        println!("    mop_n (number): {}", mop_type::n());
        println!("    mop_stack: {}", mop_type::stack());
        println!("    mop_lvar: {}", mop_type::lvar());

        // Show merror codes
        println!("\n  [Microcode Error Codes]");
        println!(
            "    merr_ok: {} = {:?}",
            merror::ok(),
            get_merror_desc(merror::ok())
        );
        println!(
            "    merr_interr: {} = {:?}",
            merror::interr(),
            get_merror_desc(merror::interr())
        );
        println!(
            "    merr_canceled: {} = {:?}",
            merror::canceled(),
            get_merror_desc(merror::canceled())
        );
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
        // Iterate over switch cases using the new iterator
        for (i, (values, body)) in insn.switch_cases().enumerate().take(3) {
            print!("{}    case {}: values=[", prefix, i);
            for (j, v) in values.iter().enumerate() {
                if j > 0 {
                    print!(", ");
                }
                print!("{}", v);
            }
            print!("]");
            if let Some(b) = body {
                println!(" -> {}", b.op_name());
            } else {
                println!(" -> (no body)");
            }
        }
    } else if op == ctype::cit_try() {
        println!("{}Try statement:", prefix);
        if let Some(body) = insn.try_first_stmt() {
            println!("{}  body: {}", prefix, body.op_name());
        }
        println!("{}  catches: {}", prefix, insn.try_catches_count());
        for i in 0..insn.try_catches_count().min(3) {
            if let Some(catch) = insn.try_catch_at(i) {
                let is_catch_all = insn.try_catch_is_catch_all(i);
                println!(
                    "{}    catch {}: {} (catch_all={})",
                    prefix,
                    i,
                    catch.op_name(),
                    is_catch_all
                );
            }
        }
    } else if op == ctype::cit_throw() {
        print!("{}Throw: ", prefix);
        if let Some(expr) = insn.throw_expr() {
            analyze_expression(&expr);
        } else {
            println!("(rethrow)");
        }
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

    // Enhanced type info using new type introspection methods
    let type_info = format_type_info(expr);

    if op == ctype::cot_num() {
        println!("number: {} ({})", expr.numval(), type_info);
    } else if op == ctype::cot_var() {
        println!("var[{}] ({})", expr.var_idx(), type_info);
    } else if op == ctype::cot_obj() {
        println!("obj @ 0x{:x} ({})", expr.obj_ea(), type_info);
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
                print!(" [{}:{}", i, a.op_name());
                if a.op() == ctype::cot_num() {
                    print!("={}", a.numval());
                } else if a.op() == ctype::cot_var() {
                    print!("=var{}", a.var_idx());
                }
                // Show if argument is a vararg
                if arg.is_vararg() {
                    print!(" (vararg)");
                }
                print!("]");
            }
        }
        println!(" -> {}", type_info);
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
    } else if op == ctype::cot_ptr() {
        // Pointer dereference - show ptr depth
        print!("deref: ");
        if let Some(x) = expr.x() {
            print!("{}", x.op_name());
        }
        println!(" (ptr_depth={}, {})", expr.type_ptr_depth(), type_info);
    } else if op == ctype::cot_ref() {
        // Address-of
        print!("ref: &");
        if let Some(x) = expr.x() {
            print!("{}", x.op_name());
        }
        println!(" ({})", type_info);
    } else if op == ctype::cot_idx() {
        // Array indexing
        print!("index: ");
        if let Some(base) = expr.x() {
            print!("{}[", base.op_name());
        }
        if let Some(idx) = expr.y() {
            print!("{}]", idx.op_name());
        }
        // Show array size if available
        let arr_size = expr.type_array_size();
        if arr_size > 0 {
            println!(" (array_size={}, {})", arr_size, type_info);
        } else {
            println!(" ({})", type_info);
        }
    } else if op == ctype::cot_cast() {
        print!("cast: ({})", expr.type_str());
        if let Some(x) = expr.x() {
            print!(" {}", x.op_name());
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
        println!(" -> {}", type_info);
    } else if decompiler::is_unary_op(op) {
        print!("{}: ", expr.op_name());
        if let Some(x) = expr.x() {
            print!("{}", x.op_name());
        }
        println!(" -> {}", type_info);
    } else {
        println!("{} ({})", expr.op_name(), type_info);
    }
}

/// Format type information using the new type introspection methods
fn format_type_info(expr: &CExpr) -> String {
    let mut info = expr.type_str();
    let mut flags = Vec::new();

    if expr.type_is_ptr() {
        flags.push(format!("ptr_depth={}", expr.type_ptr_depth()));
    }
    if expr.type_is_funcptr() {
        flags.push("funcptr".to_string());
    }
    if expr.type_is_array() {
        let size = expr.type_array_size();
        if size > 0 {
            flags.push(format!("array[{}]", size));
        } else {
            flags.push("array".to_string());
        }
    }
    if expr.type_is_struct() {
        flags.push("struct".to_string());
    }
    if expr.type_is_union() {
        flags.push("union".to_string());
    }
    if expr.type_is_enum() {
        flags.push("enum".to_string());
    }
    if expr.type_is_void() {
        flags.push("void".to_string());
    }
    if expr.type_is_pvoid() {
        flags.push("pvoid".to_string());
    }
    if expr.type_is_bool() {
        flags.push("bool".to_string());
    }
    if expr.type_is_const() {
        flags.push("const".to_string());
    }
    if expr.type_is_volatile() {
        flags.push("volatile".to_string());
    }
    if expr.type_is_float() {
        flags.push("float".to_string());
    }

    if !flags.is_empty() {
        info = format!("{} [{}]", info, flags.join(", "));
    }
    info
}
