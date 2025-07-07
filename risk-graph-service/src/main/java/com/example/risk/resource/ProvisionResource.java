package com.example.risk.resource;

import com.example.risk.service.DomainProvisioningService;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import java.util.Map;

@Path("/provision")
@Produces(MediaType.APPLICATION_JSON)
public class ProvisionResource {

    @Inject DomainProvisioningService svc;

    @POST
    @Path("/domain/{fqdn}")
    public Map<String,Object> provision(@PathParam("fqdn") String fqdn,
                                        @QueryParam("depth") @DefaultValue("1") int depth) {
        boolean created = svc.ensureDomain(fqdn, depth);
        return Map.of("created", created);
    }
}
