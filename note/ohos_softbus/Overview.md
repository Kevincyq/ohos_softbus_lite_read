D:.
│  BUILD.gn
│  LICENSE
│  README.md
│  README_zh.md
│
├─authmanager
│  │  BUILD.gn
│  │
│  ├─include
│  │      auth_conn.h
│  │      auth_interface.h
│  │      bus_manager.h
│  │      msg_get_deviceid.h
│  │      wifi_auth_manager.h
│  │
│  └─source
│          auth_conn.c
│          auth_interface.c
│          bus_manager.c
│          msg_get_deviceid.c
│          wifi_auth_manager.c
│
├─discovery
│  │  BUILD.gn
│  │
│  ├─coap
│  │  ├─include
│  │  │      coap_adapter.h
│  │  │      coap_def.h
│  │  │      coap_discover.h
│  │  │      coap_socket.h
│  │  │      json_payload.h
│  │  │      nstackx.h
│  │  │      nstackx_common.h
│  │  │      nstackx_database.h
│  │  │      nstackx_device.h
│  │  │      nstackx_error.h
│  │  │
│  │  └─source
│  │          coap_adapter.c
│  │          coap_discover.c
│  │          coap_socket.c
│  │          json_payload.c
│  │          nstackx_common.c
│  │          nstackx_device.c
│  │
│  └─discovery_service
│      ├─include
│      │      coap_service.h
│      │      common_info_manager.h
│      │      discovery_error.h
│      │
│      └─source
│              coap_service.c
│              common_info_manager.c
│              discovery_service.c
│
├─interfaces
│  └─kits
│      ├─discovery
│      │      discovery_service.h
│      │
│      └─transport
│              session.h
│
├─note
│  └─ohos_softbus
│      │  Overview.md
│      │
│      └─.obsidian
│              app.json
│              appearance.json
│              core-plugins.json
│              graph.json
│              hotkeys.json
│              workspace
│
├─os_adapter
│  ├─include
│  │      os_adapter.h
│  │
│  └─source
│      ├─L0
│      │      os_adapter.c
│      │
│      └─L1
│              os_adapter.c
│
└─trans_service
    │  BUILD.gn
    │
    ├─include
    │  ├─libdistbus
    │  │      auth_conn_manager.h
    │  │      tcp_session_manager.h
    │  │
    │  └─utils
    │          aes_gcm.h
    │          comm_defs.h
    │          data_bus_error.h
    │          message.h
    │          tcp_socket.h
    │
    └─source
        ├─libdistbus
        │      auth_conn_manager.c
        │      tcp_session.c
        │      tcp_session.h
        │      tcp_session_manager.c
        │      trans_lock.c
        │      trans_lock.h
        │
        └─utils
                aes_gcm.c
                message.c
                tcp_socket.c