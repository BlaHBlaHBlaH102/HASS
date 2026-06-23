// ============================================================
// HASS - Aho-Corasick Signature Matching Engine
// Target: Digilent Arty A7-100T (Artix-7 XC7A100T)
// ============================================================

module aho_corasick #(
    parameter NUM_STATES    = 1024,   // max trie states
    parameter ALPHABET_SIZE = 256,    // byte-level input
    parameter PATTERN_COUNT = 512,    // max patterns in table
    parameter STATE_WIDTH   = 10      // log2(NUM_STATES)
)(
    input  wire        clk,
    input  wire        rst_n,

    // Byte-stream input from MAC/TEMAC
    input  wire [7:0]  byte_in,
    input  wire        byte_valid,
    input  wire        frame_start,   // pulse: new Ethernet frame
    input  wire        frame_end,     // pulse: frame done

    // Match output
    output reg         match_found,
    output reg [9:0]   match_pattern_id,  // which pattern hit
    output reg [15:0]  match_offset,      // byte offset in frame

    // SRAM interface (for goto/fail/output tables too large for BRAM)
    output reg  [17:0] sram_addr,
    inout  wire [15:0] sram_data,
    output reg         sram_we_n,
    output reg         sram_oe_n,
    output reg         sram_ce_n
);

    // ----------------------------------------------------------
    // Internal state
    // ----------------------------------------------------------
    reg [STATE_WIDTH-1:0] current_state;
    reg [15:0]            byte_offset;
    reg                   sram_drive;
    reg [15:0]            sram_data_out;

    assign sram_data = sram_drive ? sram_data_out : 16'hZZZZ;

    // ----------------------------------------------------------
    // Goto table: stored in BRAM for single-cycle lookup
    // goto_table[state][byte] -> next_state
    // For 1024 states x 256 chars this is 256KB — too large for
    // on-chip BRAM alone; hot paths cached, cold spills to SRAM.
    // For initial prototype: reduced to 256 states fits in BRAM.
    // ----------------------------------------------------------
    // BRAM instantiation placeholder (Xilinx XPM or manual RAMB36)
    // Replace with xpm_memory_spram or RAMB36E1 primitive in Vivado
    reg [STATE_WIDTH-1:0] goto_bram [0:255][0:255];  // 256 states x 256 chars
    reg [STATE_WIDTH-1:0] fail_table [0:255];         // failure links
    reg                   output_table [0:255];       // 1 = accepting state
    reg [9:0]             output_id [0:255];          // pattern ID at accepting state

    // ----------------------------------------------------------
    // Main FSM
    // ----------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            current_state    <= 0;
            byte_offset      <= 0;
            match_found      <= 0;
            match_pattern_id <= 0;
            match_offset     <= 0;
            sram_we_n        <= 1;
            sram_oe_n        <= 1;
            sram_ce_n        <= 1;
            sram_drive       <= 0;
        end else begin
            match_found <= 0;  // default: deassert each cycle

            if (frame_start) begin
                current_state <= 0;
                byte_offset   <= 0;
            end else if (byte_valid) begin
                // Follow goto link
                $display("    DEBUG AC: byte_in=%c (0x%h) state=%0d", byte_in, byte_in, current_state);
                current_state <= goto_bram[current_state][byte_in];
                byte_offset   <= byte_offset + 1;

                // Check for match at new state
                if (output_table[goto_bram[current_state][byte_in]]) begin
                    match_found      <= 1;
                    match_pattern_id <= output_id[goto_bram[current_state][byte_in]];
                    match_offset     <= byte_offset;
                end
            end
        end
    end

    // ----------------------------------------------------------
    // NOTE: goto_bram, fail_table, output_table, output_id are
    // loaded at configuration time by MicroBlaze over the AXI
    // local bus from the nightly-updated threat pattern table.
    // A separate axi_table_loader.v module handles this write path.
    // ----------------------------------------------------------

endmodule
