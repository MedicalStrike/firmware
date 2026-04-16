#pragma once
#include "ProtobufModule.h"
#include "meshtastic/x3dh.pb.h"

/**
 * Extended Triple Diffie-Hellman for Meshtastic
 */
class X3dhModule : public ProtobufModule<meshtastic_X3DHMessage>
{
  public:
    X3dhModule() : ProtobufModule("x3dh", meshtastic_PortNum_PRIVATE_APP, &meshtastic_X3DHMessage_msg)
    {
        ourPortNum = meshtastic_PortNum_PRIVATE_APP;
    }

  protected:
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override
    {
        return p->decoded.portnum == ourPortNum || p->decoded.portnum == meshtastic_PortNum_NODEINFO_APP;
    }

    virtual bool handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_X3DHMessage *decoded) override;

    virtual meshtastic_MeshPacket *allocReply() override;
};
extern X3dhModule *x3dhModule;