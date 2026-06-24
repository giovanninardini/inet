package inet.examples.bgpv4.BgpLifecycleIpv6;

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
        channel LINK_100 extends ThruputMeteringChannel
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
        A: BgpRouter {
            parameters:
                hasIpv6 = true;
                hasStatus = true;
                @display("p=400,100");
            gates:
                pppg[1];
                ethg[1];
        }
        B: BgpRouter {
            parameters:
                hasIpv6 = true;
                hasStatus = true;
                @display("p=550,100");
            gates:
                pppg[1];
                ethg[1];
        }
        H1: StandardHost {
            parameters:
                hasIpv4 = false;
                hasIpv6 = true;
                @display("p=250,100;i=device/laptop");
            gates:
                ethg[1];
        }
        H2: StandardHost {
            parameters:
                hasIpv4 = false;
                hasIpv6 = true;
                @display("p=700,100;i=device/laptop");
            gates:
                ethg[1];
        }
    connections:
        H1.ethg[0] <--> LINK_100 <--> A.ethg[0];
        A.pppg[0] <--> LINK_100 <--> B.pppg[0];
        B.ethg[0] <--> LINK_100 <--> H2.ethg[0];
}
