package com.example.risk.resource;

import com.example.risk.service.DomainProvisioningService;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import java.util.Map;

@Path("/provision")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "Domain Provisioning", description = "Operations for provisioning domains in the risk graph")
public class ProvisionResource {

    @Inject DomainProvisioningService svc;

    @POST
    @Path("/domain/{fqdn}")
    @Operation(
        summary = "Provision a domain in the risk graph",
        description = "Creates a new domain entry in the risk graph with the specified scanning depth. " +
                     "Returns whether the domain was newly created or already existed."
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Domain provisioning completed successfully",
            content = @Content(
                mediaType = MediaType.APPLICATION_JSON,
                schema = @Schema(implementation = ProvisionResponse.class)
            )
        ),
        @APIResponse(
            responseCode = "400",
            description = "Invalid domain name or depth parameter"
        ),
        @APIResponse(
            responseCode = "500",
            description = "Internal server error during domain provisioning"
        )
    })
    public Map<String,Object> provision(
        @Parameter(
            name = "fqdn",
            description = "Fully qualified domain name to provision",
            required = true,
            example = "example.com"
        )
        @PathParam("fqdn") String fqdn,
        
        @Parameter(
            name = "depth",
            description = "Scanning depth for subdomain discovery",
            required = false,
            example = "2"
        )
        @QueryParam("depth") @DefaultValue("1") int depth
    ) {
        boolean created = svc.ensureDomain(fqdn, depth);
        return Map.of("created", created);
    }

    @Schema(name = "ProvisionResponse", description = "Response object for domain provisioning")
    public static class ProvisionResponse {
        @Schema(description = "Whether the domain was newly created", example = "true")
        public boolean created;
    }
}
