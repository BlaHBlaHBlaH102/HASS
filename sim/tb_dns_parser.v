`timescale 1ns/1ps

module tb_dns_parser;

    //-------------------------------------------------------
    // DUT Inputs
    //-------------------------------------------------------
    reg         clk         = 0;
    reg         rst_n       = 0;

    reg [7:0]   byte_in     = 0;
    reg         byte_valid  = 0;
    reg         frame_start = 0;
    reg         frame_end   = 0;

    reg         ac_match    = 0;


    //-------------------------------------------------------
    // DUT Outputs
    //-------------------------------------------------------

    wire        dns_alert;
    wire        sinkhole_active;
    wire [31:0] sinkhole_ip;
    wire [7:0]  nxdomain_count;



    //-------------------------------------------------------
    // Instantiate DUT
    //-------------------------------------------------------

    dns_parser u_dut (

        .clk(clk),
        .rst_n(rst_n),

        .byte_in(byte_in),
        .byte_valid(byte_valid),

        .frame_start(frame_start),
        .frame_end(frame_end),

        .ac_match(ac_match),

        .dns_alert(dns_alert),
        .sinkhole_active(sinkhole_active),
        .sinkhole_ip(sinkhole_ip),

        .nxdomain_count(nxdomain_count)

    );


    //-------------------------------------------------------
    // 125 MHz clock
    //-------------------------------------------------------

    always #4 clk = ~clk;



    //-------------------------------------------------------
    // VCD
    //-------------------------------------------------------

    initial begin

        $dumpfile("tb_dns_parser.vcd");
        $dumpvars(0,tb_dns_parser);

    end



    //-------------------------------------------------------
    // Send one byte
    //-------------------------------------------------------

    task send_byte;

        input [7:0] b;

        begin

            @(posedge clk);

            byte_in <= b;
            byte_valid <= 1;

            @(posedge clk);

            byte_valid <= 0;

        end

    endtask



    //-------------------------------------------------------
    // DNS query helper
    //-------------------------------------------------------

    task send_query;

        integer i;

        begin

            @(posedge clk);
            frame_start <= 1;

            @(posedge clk);
            frame_start <= 0;


            //---------------------------------------
            // Header
            //---------------------------------------

            send_byte(8'h12);
            send_byte(8'h34);

            send_byte(8'h01);
            send_byte(8'h00);

            send_byte(8'h00);
            send_byte(8'h01);

            send_byte(8'h00);
            send_byte(8'h00);

            send_byte(8'h00);
            send_byte(8'h00);

            send_byte(8'h00);
            send_byte(8'h00);



            //---------------------------------------
            // www.google.com
            //---------------------------------------

            send_byte(8'd3);
            send_byte("w");
            send_byte("w");
            send_byte("w");


            send_byte(8'd6);
            send_byte("g");
            send_byte("o");
            send_byte("o");
            send_byte("g");
            send_byte("l");
            send_byte("e");


            send_byte(8'd3);
            send_byte("c");
            send_byte("o");
            send_byte("m");


            send_byte(8'h00);



            //---------------------------------------
            // A record
            //---------------------------------------

            send_byte(8'h00);
            send_byte(8'h01);


            send_byte(8'h00);
            send_byte(8'h01);



            @(posedge clk);

            frame_end <= 1;

            @(posedge clk);

            frame_end <= 0;

        end

    endtask




    //-------------------------------------------------------
    // NXDOMAIN response helper
    //-------------------------------------------------------

    task send_nxdomain;

        begin

            @(posedge clk);
            frame_start<=1;

            @(posedge clk);
            frame_start<=0;



            send_byte(8'h12);
            send_byte(8'h34);


            // QR=1
            send_byte(8'h81);

            // RCODE=3
            send_byte(8'h83);



            repeat(8)
                send_byte(8'h00);



            send_byte(8'h00);



            @(posedge clk);

            frame_end<=1;

            @(posedge clk);

            frame_end<=0;

        end

    endtask




    //-------------------------------------------------------
    // Rebinding helper
    //-------------------------------------------------------

    task send_rebinding_response;

        integer i;

        begin

            @(posedge clk);
            frame_start<=1;

            @(posedge clk);
            frame_start<=0;



            //------------------------------------
            // DNS header
            //------------------------------------

            send_byte(8'h12);
            send_byte(8'h34);


            send_byte(8'h81);
            send_byte(8'h80);



            send_byte(8'h00);
            send_byte(8'h01);



            send_byte(8'h00);
            send_byte(8'h01);



            send_byte(8'h00);
            send_byte(8'h00);

            send_byte(8'h00);
            send_byte(8'h00);



            //------------------------------------
            // minimal qname
            //------------------------------------

            send_byte(8'h00);

            send_byte(8'h00);
            send_byte(8'h01);

            send_byte(8'h00);
            send_byte(8'h01);



            //------------------------------------
            // answer header
            //------------------------------------

            for(i=0;i<12;i=i+1)
                send_byte(8'h00);



            //------------------------------------
            // RFC1918 address
            //------------------------------------

            send_byte(8'd192);
            send_byte(8'd168);
            send_byte(8'd1);
            send_byte(8'd5);



            @(posedge clk);

            frame_end<=1;

            @(posedge clk);

            frame_end<=0;

        end

    endtask




    //-------------------------------------------------------
    // Main stimulus
    //-------------------------------------------------------

    integer k;


    initial begin


        $display("DNS Parser TB Started");


        rst_n=0;

        repeat(4)
            @(posedge clk);

        rst_n=1;

        repeat(2)
            @(posedge clk);



        //----------------------------------------------------
        // TEST 1
        //----------------------------------------------------

        $display("--------------------------------");
        $display("TEST1 Normal query");
        $display("--------------------------------");

        send_query();

        repeat(10) @(posedge clk);

        $display("alert=%b",dns_alert);



        //----------------------------------------------------
        // TEST 2
        //----------------------------------------------------

        $display("--------------------------------");
        $display("TEST2 AC match");
        $display("--------------------------------");


        ac_match=1;

        send_query();

        repeat(10)
            @(posedge clk);

        ac_match=0;


        $display("alert=%b",dns_alert);
        $display("sinkhole=%b",sinkhole_active);
        $display("ip=%h",sinkhole_ip);



        //----------------------------------------------------
        // TEST 3
        //----------------------------------------------------

        $display("--------------------------------");
        $display("TEST3 NXDOMAIN");
        $display("--------------------------------");


        send_nxdomain();

        repeat(10)
            @(posedge clk);


        $display("count=%d",
                    nxdomain_count);




        //----------------------------------------------------
        // TEST 4
        //----------------------------------------------------

        $display("--------------------------------");
        $display("TEST4 NXDOMAIN flood");
        $display("--------------------------------");


        for(k=0;k<12;k=k+1)
            send_nxdomain();


        repeat(20)
            @(posedge clk);


        $display("count=%d",
                    nxdomain_count);

        $display("alert=%b",
                    dns_alert);



        //----------------------------------------------------
        // TEST 5
        //----------------------------------------------------

        $display("--------------------------------");
        $display("TEST5 Rebinding");
        $display("--------------------------------");


        send_rebinding_response();


        repeat(20)
            @(posedge clk);



        $display("alert=%b",
                    dns_alert);




        //----------------------------------------------------
        // TEST 6
        //----------------------------------------------------

        $display("--------------------------------");
        $display("TEST6 Empty frame");
        $display("--------------------------------");


        @(posedge clk);
        frame_start<=1;

        @(posedge clk);
        frame_start<=0;


        @(posedge clk);
        frame_end<=1;

        @(posedge clk);
        frame_end<=0;


        repeat(10)
            @(posedge clk);



        $display("Simulation complete");

        $finish;


    end

endmodule