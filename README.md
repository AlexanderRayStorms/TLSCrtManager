# TLSCrtManager
If you have an HTTP server or some service that requires use of TLS certificate, a way to easily manage provisioning and update of TLS certificates is with this TLSCrtManager.

Register a project (site, API, etc) in the configuration file. Also add a path for TLSCrtManager to place an up-to-date certificate in. Then call the `TLSCrtManager` command.

Every time you call the `TLSCrtManager` command, it provisions a certificate for a project that does not have one. And for those whose certificates are about to expire, it renews theirs.

TLSCrtManager depends on LetsEncrypt's Certbot tool and a [simple web server](https://github.com/static-web-server/static-web-server). As such when installing TLSCrtManager, it would attempt to install **snap**, then attempt to install **certbot**, and then the mini web server, which listens on port 127.0.0.1:1081.

Certificates issued by this tool expire in 90 days. As such it is recommended to run the `TLSCrtManager` command at least every 89 days.

## Setup: Phase 1

    dnf   install wget zip -y
    wget  "https://github.com/AlexanderRayStorms/TLSCrtManager/archive/refs/tags/v1.x.x.zip"
    unzip v1.x.x.zip
    cd    TLSCrtManager-1.x.x
    ./Instl-01
    systemctl reboot
A reboot is necessary to complete the installation. Then log back in.

    ./Instl-02 abc@domain.com

LetsEncrypt requires the user's email address, to request a certificate from them. Provide your email address as an argument to `Instl-02`. It could be any email address.

## Setup: Phase 2
The use case of TLSCrtManager is a main project that wants to outsource TLS certificate management to a secondary tool. As such, it is assumed you already have an HTTP server set up.

For the domain you want to set up certificate management for, ensure that public requests to path `/.well-known/acme-challenge` (and its sub-paths) are forwarded to http://127.0.0.1:1081.

## Project setup
Setting up a project (a domain whose TLS certificate should be managed) is done in the `/etc/TLSCrtManager/Cnf` configuration file.

Just add a new project entry and populate the parameters.

Project ID should be a UUID v4 ID, e.g. `5454f7c4-45d0-45f1-b6ab-686ee0fbede8`. You can generate one here: https://www.uuidgenerator.net/version4

## Run
After you must have registered your projects, the next thing is to call the TLSCrtManager command:

    TLSCrtManager

In addition to printing logs to the console. TLSCrtManager also logs output to file /etc/TLSCrtManager/Cnf.

## Update

    TLSCrtManager-Update abc@domain.com

LetsEncrypt requires the user's email address, to request a certificate from them. Provide your email address as an argument to `Instl-02`. It could be any email address.