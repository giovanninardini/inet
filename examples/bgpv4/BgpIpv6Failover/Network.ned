package inet.examples.bgpv4.BgpIpv6Failover;

import inet.common.misc.ThruputMeteringChannel;
import inet.common.scenario.ScenarioManager;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.networklayer.configurator.ipv6.Ipv6NetworkConfigurator;
import inet.node.bgp.BgpRouter;
import inet.node.inet.StandardHost;
import inet.visualizer.canvas.integrated.IntegratedCanvasVisualizer;

network BgpNetwork
{
    types:
        channel LINK_PRIMARY extends ThruputMeteringChannel
        {
            parameters:
                delay = 50us;
                datarate = 100Mbps;
                displayAsTooltip = true;
                thruputDisplayFormat = "#N";
        }
        channel LINK_BACKUP extends ThruputMeteringChannel
        {
            parameters:
                delay = 5ms;
                datarate = 100Mbps;
                displayAsTooltip = true;
                thruputDisplayFormat = "#N";
        }
        channel LINK_LAN extends ThruputMeteringChannel
        {
            parameters:
                delay = 50us;
                datarate = 100Mbps;
                displayAsTooltip = true;
                thruputDisplayFormat = "#N";
        }
    submodules:
        visualizer: IntegratedCanvasVisualizer {
            parameters:
                @display("p=100,100;is=s");
        }
        configurator: Ipv4NetworkConfigurator {
            parameters:
                @display("p=100,200;is=s");
                config = xmldoc("IPv4Config.xml");
                addStaticRoutes = false;
                addDefaultRoutes = false;
                addSubnetRoutes = false;
        }
        configurator6: Ipv6NetworkConfigurator {
            parameters:
                @display("p=100,300;is=s");
                config = xmldoc("IPv6Config.xml");
                addStaticRoutes = false;
                addDefaultRoutes = false;
        }
        scenarioManager: ScenarioManager {
            parameters:
                @display("p=100,400;is=s");
        }
        H1: StandardHost {
            parameters:
                hasIpv4 = false;
                hasIpv6 = true;
                @display("p=250,250;i=device/laptop");
            gates:
                ethg[1];
        }
        A: BgpRouter {
            parameters:
                hasIpv6 = true;
                hasStatus = true;
                @display("p=450,250");
            gates:
                ethg[1];
                pppg[2];
        }
        B: BgpRouter {
            parameters:
                hasIpv6 = true;
                hasStatus = true;
                @display("p=650,120");
            gates:
                pppg[2];
        }
        C: BgpRouter {
            parameters:
                hasIpv6 = true;
                hasStatus = true;
                @display("p=650,380");
            gates:
                pppg[2];
        }
        D: BgpRouter {
            parameters:
                hasIpv6 = true;
                hasStatus = true;
                @display("p=850,250");
            gates:
                ethg[1];
                pppg[2];
        }
        H2: StandardHost {
            parameters:
                hasIpv4 = false;
                hasIpv6 = true;
                @display("p=1050,250;i=device/laptop");
            gates:
                ethg[1];
        }
    connections:
        H1.ethg[0] <--> LINK_LAN <--> A.ethg[0];
        A.pppg[0] <--> LINK_PRIMARY <--> B.pppg[0];
        B.pppg[1] <--> LINK_PRIMARY <--> D.pppg[0];
        A.pppg[1] <--> LINK_BACKUP <--> C.pppg[0];
        C.pppg[1] <--> LINK_BACKUP <--> D.pppg[1];
        D.ethg[0] <--> LINK_LAN <--> H2.ethg[0];
}
