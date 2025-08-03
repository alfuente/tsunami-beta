package com.example.warehouse.resource;

import com.example.warehouse.dao.IcebergDAO;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;

@Path("/snapshot")
public class SnapshotResource {

    @Inject IcebergDAO dao;

    @POST
    @Path("/domain")
    public Response snap(@QueryParam("fqdn") String fqdn){
        if (fqdn==null || fqdn.isBlank()) throw new BadRequestException("fqdn is required");
        dao.snapshotDomain(fqdn);
        return Response.ok().build();
    }
}
