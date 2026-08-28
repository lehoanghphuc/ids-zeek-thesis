module CustomDetect;

export {
    redef enum Notice::Type += {
        Port_Scan,
        SSH_Bruteforce,
        SYN_Flood
    };
}

global scan_tracker: table[addr] of set[port] &create_expire=1min;
global ssh_fail_tracker: table[addr] of count &create_expire=1min &default=0;
global syn_tracker: table[addr] of count &create_expire=10sec &default=0;

event connection_state_remove(c: connection)
    {
    local orig = c$id$orig_h;
    local resp_p = c$id$resp_p;

    # --- Port scan: dem so port khac nhau tu 1 nguon ---
    if ( orig !in scan_tracker )
        scan_tracker[orig] = set();
    add scan_tracker[orig][resp_p];

    if ( |scan_tracker[orig]| > 15 )
        {
        NOTICE([$note=Port_Scan,
                $msg=fmt("Possible port scan from %s (%d ports)", orig, |scan_tracker[orig]|),
                $src=orig]);
        }

    # --- SYN flood: dem so ket noi REJ/S0 toi cung dich trong thoi gian ngan ---
    if ( c$conn$conn_state == "REJ" || c$conn$conn_state == "S0" )
        {
        ++syn_tracker[orig];
        if ( syn_tracker[orig] > 30 )
            {
            NOTICE([$note=SYN_Flood,
                    $msg=fmt("Possible SYN flood from %s (%d attempts)", orig, syn_tracker[orig]),
                    $src=orig]);
            }
        }
    if ( resp_p == 22/tcp )
        {
        ++ssh_fail_tracker[orig];
        if ( ssh_fail_tracker[orig] > 4 )
            {
            NOTICE ([$note=SSH_Bruteforce,
                     $msg=fmt("Possible SSH brute-force from %s (%d connection attempt)", orig, ssh_fail_tracker[orig]),
                     $src=orig]);
            }
        }
    }

