#include "X3dhModule.h"
#include "CryptoEngine.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "meshtastic/x3dh_payload.pb.h"

bool X3dhModule::handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_X3DHMessage *decoded)
{
    bool toReturn = false;
    if (decoded == NULL && mp.which_payload_variant == meshtastic_PortNum_NODEINFO_APP) {
        meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
        if (node == NULL) {
            LOG_WARN("Node %s not found in Database, aborting.", node->num);
        } else {
            bool usesX3dh = node->bitfield & NODEINFO_BITFIELD_USES_X3DH_MASK;
            if (usesX3dh) {
                LOG_INFO("Already started X3DH for Node %s", node->num);
            } else {
                meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
                auto x3dhMessage = allocDataProtobuf(init);
                x3dhMessage->to = mp.from;
                x3dhMessage->pki_encrypted = true;
                memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
                x3dhMessage->decoded.want_response = true;
                service->sendToMesh(x3dhMessage);
                node->bitfield ^= NODEINFO_BITFIELD_USES_X3DH_MASK;
            }
        }
    } else {
        switch (decoded->type) {
        case meshtastic_X3DHMessageType_EXTERNAL_BUNDLE:
            /* code */
            break;

        case meshtastic_X3DHMessageType_RESPONSE_BUNDLE:
            break;

        case meshtastic_X3DHMessageType_X3DH_ERROR:
            break;

        default:
            break;
        }
    }
    return toReturn;
}

meshtastic_MeshPacket *X3dhModule::allocReply()
{
    switch (expression) {
    case constant expression:
        /* code */
        break;

    default:
        break;
    }
}