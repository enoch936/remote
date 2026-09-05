package com.company.remoteaccess.networking;

import java.util.ArrayList;
import java.util.List;

/**
 * Describes the routes the application intends to create or tear down.
 * The default is split-tunnel (company resources only); full-tunnel is opt-in
 * by an administrator.
 */
public final class RoutePlan {

    public enum Mode { SPLIT_TUNNEL, FULL_TUNNEL }

    private Mode mode = Mode.SPLIT_TUNNEL;
    private final List<IpHelpers.Cidr> companySubnets = new ArrayList<>();
    private final List<IpHelpers.Cidr> extraSubnets = new ArrayList<>();
    private String tunnelInterfaceName;
    private String tunnelGatewayIp;
    /** Public endpoint of the gateway (needed to pin it out of the tunnel in full mode). */
    private String serverPublicEndpoint;

    public RoutePlan mode(Mode mode) {
        this.mode = mode == null ? Mode.SPLIT_TUNNEL : mode;
        return this;
    }

    public RoutePlan companySubnet(IpHelpers.Cidr subnet) {
        companySubnets.add(subnet);
        return this;
    }

    public RoutePlan extraSubnet(IpHelpers.Cidr subnet) {
        extraSubnets.add(subnet);
        return this;
    }

    public RoutePlan tunnelInterface(String name, String gatewayIp) {
        this.tunnelInterfaceName = name;
        this.tunnelGatewayIp = gatewayIp;
        return this;
    }

    public RoutePlan serverPublicEndpoint(String endpoint) {
        this.serverPublicEndpoint = endpoint;
        return this;
    }

    public Mode mode() {
        return mode;
    }

    public List<IpHelpers.Cidr> companySubnets() {
        return List.copyOf(companySubnets);
    }

    public List<IpHelpers.Cidr> extraSubnets() {
        return List.copyOf(extraSubnets);
    }

    public List<IpHelpers.Cidr> allRoutedSubnets() {
        List<IpHelpers.Cidr> all = new ArrayList<>(companySubnets);
        all.addAll(extraSubnets);
        return List.copyOf(all);
    }

    public String tunnelInterfaceName() {
        return tunnelInterfaceName;
    }

    public String tunnelGatewayIp() {
        return tunnelGatewayIp;
    }

    public String serverPublicEndpoint() {
        return serverPublicEndpoint;
    }
}