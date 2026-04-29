pub fn generate_solvency_challenge_script_v3() -> Script {
    script! {
        OP_3 OP_MUL
        OP_SWAP
        OP_2 OP_MUL
        OP_LESSTHANOREQUAL
        OP_VERIFY
    }
}
