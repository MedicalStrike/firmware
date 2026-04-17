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
            bool usesX3dh = node->user.has_x3dh_shared_key;
            if (usesX3dh) {
                LOG_INFO("X3DH-Agreement already finished for Node %s", node->num);
            } else {
                if (!node->user.has_x3dh_state || node->user.x3dh_state == meshtastic_X3DHState_X3DH_NOT_STARTED) {
                    meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
                    meshtastic_RequestBundle initBundle = meshtastic_RequestBundle_init_default;
                    initBundle.node_num = mp.from;
                    memcpy(initBundle.public_key, mp.public_key.bytes, 32);
                    uint8_t initPayloadBytes[meshtastic_RequestBundle_size] = {0};
                    pb_encode_to_bytes(initPayloadBytes, meshtastic_RequestBundle_size, meshtastic_RequestBundle_fields,
                                       &initBundle);
                    memcpy(init.payload.bytes, initPayloadBytes, meshtastic_RequestBundle_size);
                    auto x3dhMessage = allocDataProtobuf(init);
                    x3dhMessage->to = mp.from;
                    x3dhMessage->pki_encrypted = true;
                    memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
                    x3dhMessage->decoded.want_response = true;
                    node->user.x3dh_state = meshtastic_X3DHState_BUNDLE_REQUESTED;
                    service->sendToMesh(x3dhMessage);
                } else {
                    LOG_INFO("X3DH-Agreement already started for Node %s", node->num);
                }
            }
        }
    } else {
        switch (decoded->type) {
        case meshtastic_X3DHMessageType_EXTERNAL_BUNDLE:
            meshtastic_RequestBundle bundle;
            memset(&bundle, 0, sizeof(bundle));
            meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
            NodeNum to;
            if (pb_decode_from_bytes(decoded->payload.bytes, sizeof(decoded->payload.bytes), meshtastic_RequestBundle_fields,
                                     &bundle)) {
                to = bundle.node_num;
                meshtastic_NodeInfoLite *serverNode = nodeDB->getMeshNode(to);
                if (serverNode == NULL) {
                    LOG_WARN("No node found for ID %s", to);
                    break;
                } else {
                    meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
                    if (memcmp(bundle.public_key, serverNode->user.public_key.bytes, 32)) {
                        meshtastic_RequestBundle initBundle = meshtastic_RequestBundle_init_default;
                        initBundle.node_num = mp.from;
                        memcpy(initBundle.public_key, mp.public_key.bytes, 32);
                        uint8_t initPayloadBytes[meshtastic_RequestBundle_size] = {0};
                        pb_encode_to_bytes(initPayloadBytes, meshtastic_RequestBundle_size, meshtastic_RequestBundle_fields,
                                           &initBundle);
                        memcpy(init.payload.bytes, initPayloadBytes, meshtastic_RequestBundle_size);
                        LOG_INFO("Sending RequestBundle to Server %s for Pre-Key-Bundle for Node %s", to, mp.from);
                        meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
                        node->user.x3dh_state = meshtastic_X3DHState_EXTERNAL_BUNDLE_REQUESTED;
                    } else {
                        LOG_WARN("Server public key mismatch, aborting X3DH handshake");
                        init.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                        memcpy(init.payload.bytes, decoded->payload.bytes, decoded->payload.size);
                        to = mp.from;
                        // Reset state so we can try again on next NodeInfo-packet
                        node->user.x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                    }
                }
            } else {
                LOG_WARN("Payload protobuf decode failed. Invalid payload type for EXTERNAL_BUNDLE");
                init.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                to = mp.from;
            }
            auto x3dhServerMessage = allocDataProtobuf(init);
            x3dhServerMessage->pki_encrypted = true;
            memcpy(x3dhServerMessage->public_key.bytes, crypto->public_key, x3dhServerMessage->public_key.size);
            x3dhServerMessage->to = to;
            break;

        case meshtastic_X3DHMessageType_PROTOCOL_SWITCH:
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
            if (node->user.x3dh_state == meshtastic_X3DHState_INIT_SENT && node->user.has_x3dh_shared_key) {
                LOG_INFO("Confirmed usage of X3DH-Secret for future direct messages with node %s", mp.from);
                node->bitfield |= NODEINFO_BITFIELD_USES_X3DH_MASK;
                node->user.x3dh_state = meshtastic_X3DHState_PROTOCOL_SET;
            } else {
            }
            break;

        case meshtastic_X3DHMessageType_X3DH_ERROR:
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
            if ((node->bitfield & NODEINFO_BITFIELD_USES_X3DH_MASK) && node->user.has_x3dh_shared_key) {
                LOG_WARN("Attempted X3DH-Downgrade-Attack! NodeInfo-Bit is not cleared!");
            } else if ((node->bitfield & NODEINFO_BITFIELD_USES_X3DH_MASK)) {
                meshtastic_RequestBundle bundle;
                memset(&bundle, 0, sizeof(bundle));
                if (pb_decode_from_bytes(decoded->payload.bytes, sizeof(decoded->payload.bytes), meshtastic_RequestBundle_fields,
                                         &bundle)) {
                    LOG_WARN
                }
            }
            break;

        default:
            break;
        }
    }
    return toReturn;
}

meshtastic_MeshPacket *X3dhModule::allocReply()
{
    /*
    switch (expression) {
    case constant expression:

        break;

    default:
        break;
    }
    */
}