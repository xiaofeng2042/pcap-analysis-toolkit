event new_connection(c: connection)
{
    print fmt("[NEW_CONNECTION] %s:%d -> %s:%d", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}

event connection_established(c: connection)
{
    print fmt("[ESTABLISHED] %s:%d -> %s:%d", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}

event connection_state_remove(c: connection)
{
    print fmt("[REMOVED] %s:%d -> %s:%d", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}
