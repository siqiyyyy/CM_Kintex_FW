library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use work.axiRegPkg.all;
use work.TCDS_Ctrl.all;
use work.types.all;

Library UNISIM;
use UNISIM.vcomponents.all;


entity TCDS is
  
  port (
    clk_axi              : in  std_logic;
    reset_axi_n          : in  std_logic;
    readMOSI             : in  AXIreadMOSI;
    readMISO             : out AXIreadMISO;
    writeMOSI            : in  AXIwriteMOSI;
    writeMISO            : out AXIwriteMISO;
    DRP_readMOSI         : in  AXIreadMOSI;
    DRP_readMISO         : out AXIreadMISO;
    DRP_writeMOSI        : in  AXIwriteMOSI;
    DRP_writeMISO        : out AXIwriteMISO;
    refclk_p : in std_logic;
    refclk_n : in std_logic;
    tx_p : out std_logic;
    tx_n : out std_logic;
    rx_p : in  std_logic;
    rx_n : in  std_logic);

end entity TCDS;

architecture behavioral of TCDS is
  signal refclk : std_logic;

  signal clk_rx_int     : std_logic;
  signal clk_rx_int_raw : std_logic;
  signal clk_tx_int     : std_logic;
  signal clk_tx_int_raw : std_logic;
  
  type DRP_t is record
    en   : STD_LOGIC;
    we   : STD_LOGIC;
    addr : STD_LOGIC_VECTOR ( 8 downto 0 );
    di   : STD_LOGIC_VECTOR ( 15 downto 0 );
    do   : STD_LOGIC_VECTOR ( 15 downto 0 );
    rdy  : STD_LOGIC;
  end record DRP_t;
  signal drp_intf : DRP_t;

  signal Mon              :  TCDS_Mon_t;
  signal Ctrl             :  TCDS_Ctrl_t;

  
begin  -- architecture TCDS

  reflk_buf : IBUFDS_GTE4
    generic map (
      REFCLK_EN_TX_PATH => '0',
      REFCLK_HROW_CK_SEL => "00",
      REFCLK_ICNTL_RX    => "00")
    port map (
      I     => refclk_p,        
      IB    => refclk_n,
      CEB   => '0',
      O     => refclk,  
      ODIV2 => open);

  
  --Convert QPLL clock to tx clocks
  --BUFG_GT
  clk_tx_int_buf : BUFG_GT
    port map (
      CE      => '1',
      CEMASK  => '0',
      CLR     => '0',
      CLRMASK => '0',
      DIV     => "000",
      I       => clk_tx_int_raw,
      O       => clk_tx_int);
    
  clk_rx_int_buf : BUFG_GT
    port map (
      CE      => '1',
      CEMASK  => '0',
      CLR     => '0',
      CLRMASK => '0',
      DIV     => "000",
      I       => clk_rx_int_raw,
      O       => clk_rx_int);


  TCDS_interface_1: entity work.TCDS_interface
    port map (
      clk_axi         => clk_axi,
      reset_axi_n     => reset_axi_n,
      slave_readMOSI  => readMOSI,
      slave_readMISO  => readMISO,
      slave_writeMOSI => writeMOSI,
      slave_writeMISO => writeMISO,
      Mon             => Mon,
      Ctrl            => Ctrl);
  
  TCDS_TxRx_2: entity work.TCDS_TxRx
    port map (
      gtwiz_userclk_tx_active_in            => "1",
      gtwiz_userclk_rx_active_in            => "1",
      gtwiz_reset_clk_freerun_in(0)         => clk_axi,
      gtwiz_reset_all_in(0)                 => Ctrl.RESETS.RESET_ALL,
      gtwiz_reset_tx_pll_and_datapath_in(0) => Ctrl.RESETS.TX_PLL_DATAPATH,
      gtwiz_reset_tx_datapath_in(0)         => Ctrl.RESETS.TX_DATAPATH,
      gtwiz_reset_rx_pll_and_datapath_in(0) => Ctrl.RESETS.RX_PLL_DATAPATH,
      gtwiz_reset_rx_datapath_in(0)         => Ctrl.RESETS.RX_DATAPATH,
      gtwiz_reset_rx_cdr_stable_out(0)      => Mon.CLOCKING.RX_CDR_STABLE,
      gtwiz_reset_tx_done_out(0)            => Mon.RESETS.TX_RESET_DONE,
      gtwiz_reset_rx_done_out(0)            => Mon.RESETS.RX_RESET_DONE,
      gtwiz_userdata_tx_in               => tx_data,
      gtwiz_userdata_rx_out              => rx_data,    
      gtrefclk00_in(0)                   => refclk,
      qpll0outclk_out                    => open,
      qpll0outrefclk_out                 => open,
      drpaddr_in                         => drp_intf.addr,
      drpclk_in(0)                       => clk_axi,
      drpdi_in                           => drp_intf.di,
      drpen_in                           => drp_intf.en,
      drpwe_in                           => drp_intf.we,
      eyescanreset_in(0)                 => Ctrl.EYESCAN.RESET,
      eyescantrigger_in(0)               => Ctrl.EYESCAN.TRIGGER,
      gthrxn_in(0)                       => rx_n,
      gthrxp_in(0)                       => rx_p,
      loopback_in                        => CTRL.LOOPBACK,
      rx8b10ben_in                       => "1",
      rxcommadeten_in                    => "1",
      rxlpmen_in                         => "X",
      rxmcommaalignen_in                 => "1",
      rxpcommaalignen_in                 => "1",
      rxprbscntreset_in(0)               => Ctrl.RX.PRBS_RESET,
      rxprbssel_in                       => Ctrl.RX.PRBS_SEL,
      rxrate_in                          => "000",
      rxusrclk_in                        => clk_rx_int,
      rxusrclk2_in                       => clk_rx_int,
      tx8b10ben_in                       => "1",
      txctrl0_in                         => x"0000",
      txctrl1_in                         => x"0000",
      txctrl2_in( 3 downto  0)           => tx_k_data,
      txctrl2_in( 7 downto  0)           => (others => '0'),
      txdiffctrl_in                      => (others => 'X'),
      txinhibit_in(0)                    => Ctrl.TX.INHIBIT,
      txpostcursor_in                    => (others => 'X'),
      txprbsforceerr_in(0)               => Ctrl.TX.PRBS_FORCE_ERROR,
      txprbssel_in                       => Ctrl.TX.PRBS_SEL,
      txprecursor_in                     => (others => 'X'),
      txusrclk_in                        => clk_tx_int,
      txusrclk2_in                       => clk_tx_int,
      drpdo_out                          => drp_intf.do,
      drprdy_out                         => drp_intf.rdy,
      gthtxn_out                         => tx_n,
      gthtxp_out                         => tx_p,
      gtpowergood_out(0)                 => Mon.CLOCKING.POWER_GOOD,
      rxbyteisaligned_out                => open,
      rxbyterealign_out                  => open,
      rxcommadet_out                     => open,
      rxctrl0_out( 3 downto  0)          => rx_k_data,
      rxctrl0_out(15 downto  4)          => open,
      rxctrl1_out( 3 downto  0)          => Mon.RX.DISP_ERROR,
      rxctrl1_out(15 downto  4)          => open,
      rxctrl2_out                        => open,
      rxctrl3_out( 3 downto  0)          => Mon.RX.BAD_CHAR,
      rxctrl3_out( 7 downto  4)          => open,
      rxdata_out                         => open, 
      rxoutclk_out                       => clk_rx_int_raw,
      rxpmaresetdone_out(0)              => Mon.RX_PMA_RESET_DONE,
      txoutclk_out                       => clk_tx_int_raw,
      txpmaresetdone_out(0)              => Mon.TX_PMA_RESET_DONE);



  AXI_DRP_1: entity work.AXI_DRP
    port map (
      AXI_aclk      => clk_axi,
      AXI_aresetn   => reset_axi_n,
      S_AXI_araddr  => DRP_readMOSI.address,
      S_AXI_arready => DRP_readMISO.ready_for_address,
      S_AXI_arvalid => DRP_readMOSI.address_valid,
      S_AXI_arprot  => DRP_readMOSI.protection_type,
      S_AXI_awaddr  => DRP_writeMOSI.address,
      S_AXI_awready => DRP_writeMISO.ready_for_address,
      S_AXI_awvalid => DRP_writeMOSI.address_valid,
      S_AXI_awprot  => DRP_writeMOSI.protection_type,
      S_AXI_bresp   => DRP_writeMISO.response,
      S_AXI_bready  => DRP_writeMOSI.ready_for_response,
      S_AXI_bvalid  => DRP_writeMISO.response_valid,
      S_AXI_rdata   => DRP_readMISO.data,
      S_AXI_rready  => DRP_readMOSI.ready_for_data,
      S_AXI_rvalid  => DRP_readMISO.data_valid,
      S_AXI_rresp   => DRP_readMISO.response,
      S_AXI_wdata   => DRP_writeMOSI.data,
      S_AXI_wready  => DRP_writeMISO.ready_for_data,
      S_AXI_wvalid  => DRP_writeMOSI.data_valid,
      S_AXI_wstrb   => DRP_writeMOSI.data_write_strobe,
      drp0_en       => drp_intf.en,
      drp0_we       => drp_intf.we,
      drp0_addr     => drp_intf.addr,
      drp0_di       => drp_intf.di,
      drp0_do       => drp_intf.do,
      drp0_rdy      => drp_intf.rdy);

end architecture TCDS;
