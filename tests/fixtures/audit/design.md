# Assistant design

The memory service serves multiple tenants. Each request carries a caller identity.
The design says nothing about how memory queries bind the tenant namespace.
No implementation or runtime observations are provided.
