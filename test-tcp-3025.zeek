event new_connection(c: connection)
{
    if (c$id$resp_p == 3025/tcp || c$id$orig_p == 3025/tcp) {
        print fmt("[TCP-3025] New connection: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}

event connection_established(c: connection)
{
    if (c$id$resp_p == 3025/tcp || c$id$orig_p == 3025/tcp) {
        print fmt("[TCP-3025] Established: %s:%d -> %s:%d", 
                  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}
