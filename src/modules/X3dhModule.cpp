#include "X3dhModule.h"
#include "Crypto.h"
#include "CryptoEngine.h"
#include "Curve25519.h"
#include "FSCommon.h"
#include "HKDF.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "RNG.h"
#include "SHA512.h"
#include "SPILock.h"
#include "aes-ccm.h"
#include "meshUtils.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include <string>

std::random_device randDev;
std::minstd_rand x3dhRandom(randDev());
meshtastic_PreKeyStorage x3dhDB;
std::vector<meshtastic_OneTimePreKey> *otpks;
meshtastic_X3DHStateDB x3dhStateDb;
std::vector<meshtastic_X3DHNodeInfo> *states;

bool X3dhModule::handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_X3DHMessage *decoded)
{
    bool toReturn = false;
    LOG_DEBUG("Starting to process message with PortNum %d", mp.decoded.portnum);
    // if (decoded == NULL && mp.which_payload_variant == meshtastic_PortNum_NODEINFO_APP) {
    //     meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
    //     if (node == NULL) {
    //         LOG_WARN("Node %s not found in Database, aborting.", node->num);
    //     } else {
    //         bool usesX3dh = node->user.has_x3dh_shared_key;
    //         if (usesX3dh) {
    //             LOG_INFO("X3DH-Agreement already finished for Node %s", node->num);
    //         } else {
    //             if (!node->user.has_x3dh_state || node->user.x3dh_state == meshtastic_X3DHState_X3DH_NOT_STARTED) {
    //                 meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
    //                 meshtastic_RequestBundle initBundle = meshtastic_RequestBundle_init_default;
    //                 initBundle.node_num = mp.from;
    //                 memcpy(initBundle.public_key, mp.public_key.bytes, 32);
    //                 uint8_t initPayloadBytes[meshtastic_RequestBundle_size] = {0};
    //                 pb_encode_to_bytes(initPayloadBytes, meshtastic_RequestBundle_size, meshtastic_RequestBundle_fields,
    //                                    &initBundle);
    //                 memcpy(init.payload.bytes, initPayloadBytes, meshtastic_RequestBundle_size);
    //                 auto x3dhMessage = allocDataProtobuf(init);
    //                 x3dhMessage->to = mp.from;
    //                 x3dhMessage->pki_encrypted = true;
    //                 memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
    //                 x3dhMessage->decoded.want_response = true;
    //                 node->user.x3dh_state = meshtastic_X3DHState_BUNDLE_REQUESTED;
    //                 service->sendToMesh(x3dhMessage);
    //             } else {
    //                 LOG_INFO("X3DH-Agreement already started for Node %s", node->num);
    //             }
    //         }
    //     }
    if (mp.decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP) {
        char messageArray[10] = "startX3DH";
        auto &p = mp.decoded;
        LOG_INFO("Received text msg from=0x%0x, id=0x%x, msg=%.*s", mp.from, mp.id, p.payload.size, p.payload.bytes);
        if (memcmp(messageArray, p.payload.bytes, p.payload.size)) {
            LOG_INFO("Message from 0x%0x does not contain the keyword to start an X3DH-agreement.", mp.from);
        } else {
            bool usesX3dh = (nodeDB->getMeshNode(mp.from)->bitfield & NODEINFO_BITFIELD_USES_X3DH_MASK);
            LOG_INFO("Node has state %d", usesX3dh);
            meshtastic_X3DHNodeInfo *state = getOrCreateNodeStateEntry(mp.from);
            if (!usesX3dh) {
                if (true) { // state->x3dh_state == meshtastic_X3DHState_X3DH_NOT_STARTED) {
                    meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
                    init.type = meshtastic_X3DHMessageType_REQUEST_BUNDLE;
                    memcpy(init.identity_key, mp.public_key.bytes, 32);
                    init.node_num = getFrom(&mp);
                    auto x3dhMessage = allocDataProtobuf(init);
                    size_t testSize;
                    pb_get_encoded_size(&testSize, &meshtastic_X3DHMessage_msg, &init);
                    LOG_INFO("Message payload should have size: %d", testSize);
                    LOG_INFO("Message has size: %d", x3dhMessage->decoded.payload.size);
                    x3dhMessage->to = mp.from;
                    x3dhMessage->pki_encrypted = true;
                    memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
                    x3dhMessage->decoded.want_response = true;
                    x3dhMessage->want_ack = true;
                    // state->x3dh_state = meshtastic_X3DHState_BUNDLE_REQUESTED; // TODO fix when all works
                    service->sendToMesh(x3dhMessage);
                } else {
                    LOG_INFO("X3DH-Agreement already started for Node 0x%0x", state->node_num);
                }
            } else {
                LOG_INFO("X3DH-Agreement already finished for Node 0x%0x", state->node_num);
            }
            toReturn = true;
        }
    } else {
        LOG_INFO("Payload has X3DH-type %d, sub-payload has size: %d", decoded->type, sizeof(mp.decoded.payload.bytes));
        x3dhReply = meshtastic_X3DHMessage_init_default;
        meshtastic_X3DHNodeInfo *nodeInfo = getOrCreateNodeStateEntry(mp.from);
        switch (decoded->type) {
        case meshtastic_X3DHMessageType_REQUEST_BUNDLE: {
            LOG_INFO("Recieved request for pre-key bundle, starting work on response");
            LOG_WARN("X3DH-DB node num: %d, myNodeInfo node num: %d", x3dhDB.node_num, myNodeInfo.my_node_num);
            if (x3dhDB.node_num == 0) {
                LOG_INFO("Key bundle stored locally, creating response bundle");
                x3dhReply.type = meshtastic_X3DHMessageType_RESPONSE_BUNDLE;
                x3dhReply.node_num = myNodeInfo.my_node_num;
                memcpy(x3dhReply.identity_key, crypto->public_key, 32);
                LOG_INFO("PubKey copied!");
                uint8_t tempPubKey[32] = {0};
                Curve25519::eval(tempPubKey, x3dhDB.signed_pre_key,
                                 0); // No need to check for weak points since the generator function did this for the private key
                memcpy(x3dhReply.signed_pre_key, tempPubKey, 32);
                LOG_INFO("PreKey copied!");
                clean(tempPubKey);
                memcpy(x3dhReply.pre_key_signature, x3dhDB.pre_key_signature, 64);
                LOG_INFO("Signature copied!");
                x3dhReply.one_time_pre_key = meshtastic_OneTimePreKey_init_default;
                for (auto iterator = otpks->begin(); iterator != otpks->end(); ++iterator) {
                    meshtastic_OneTimePreKey *current = &*iterator;
                    LOG_INFO("Current OTPK ID: %d", current->id);
                    LOG_INFO("Current node num: %d", current->node_num);
                    printBytes("Current stored key: ", current->key, 32);
                    if (current->node_num == 0) {
                        current->node_num = getFrom(&mp);
                        x3dhReply.one_time_pre_key.node_num = current->node_num;
                        x3dhReply.one_time_pre_key.id = current->id;
                        Curve25519::eval(
                            tempPubKey, current->key,
                            0); // No need to check for weak points since the generator function did this for the private key
                        memcpy(x3dhReply.one_time_pre_key.key, tempPubKey, 32);
                        clean(tempPubKey);
                        break;
                    }
                }
                if (x3dhReply.one_time_pre_key.id == 0) {
                    LOG_WARN("No free one-time pre-keys found, aborting X3DH-agreement");
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                } else {
                    LOG_INFO("One-time pre-key with id %0x will be used", x3dhReply.one_time_pre_key.id);
                    nodeInfo->x3dh_state = meshtastic_X3DHState_BUNDLE_SENT;
                }
            } else {
                meshtastic_NodeInfoLite *server = nodeDB->getMeshNode(x3dhDB.node_num);
                x3dhReply.type = meshtastic_X3DHMessageType_EXTERNAL_BUNDLE;
                x3dhReply.node_num = x3dhDB.node_num;
                memcpy(x3dhReply.identity_key, &server->user.public_key, 32);
                nodeInfo->x3dh_state = meshtastic_X3DHState_BUNDLE_SENT;
            }
            break;
        }

        case meshtastic_X3DHMessageType_EXTERNAL_BUNDLE: {
            NodeNum to;
            to = decoded->node_num;
            meshtastic_NodeInfoLite *serverNode = nodeDB->getMeshNode(to);
            if (serverNode == NULL) {
                LOG_WARN("No node found for ID %s", to);
                break;
            } else {
                if (memcmp(decoded->identity_key, serverNode->user.public_key.bytes, 32)) {
                    x3dhReply.node_num = mp.from;
                    memcpy(x3dhReply.identity_key, mp.public_key.bytes, 32);
                    LOG_INFO("Sending RequestBundle to Server %s for Pre-Key-Bundle for Node %s", to, mp.from);
                    nodeInfo->x3dh_state = meshtastic_X3DHState_EXTERNAL_BUNDLE_REQUESTED;
                } else {
                    LOG_WARN("Server public key mismatch, aborting X3DH handshake");
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    to = mp.from;
                    // Reset state so we can try again on next NodeInfo-packet
                    nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                }
            }

            auto x3dhServerMessage = allocDataProtobuf(x3dhReply);
            x3dhServerMessage->pki_encrypted = true;
            memcpy(x3dhServerMessage->public_key.bytes, crypto->public_key, x3dhServerMessage->public_key.size);
            x3dhServerMessage->to = to;
            service->sendToMesh(x3dhServerMessage);
            break;
        }

        case meshtastic_X3DHMessageType_RESPONSE_BUNDLE: {
            NodeNum to = mp.from;
            nodeInfo = getOrCreateNodeStateEntry(decoded->node_num);
            uint8_t userKey[32] = {0};
            memcpy(userKey, &nodeDB->getMeshNode(decoded->node_num)->user.public_key, 32);
            LOG_INFO("Response bundle recieved from %0x", decoded->node_num);
            printBytes("Payload key: ", decoded->identity_key, 32);
            printBytes("Node key: ", userKey, 32);
            if (memcmp(decoded->identity_key, userKey, 32)) {
                LOG_INFO("Identity key matches, checking for one-time pre keys");
                if (decoded->has_one_time_pre_key) {
                    LOG_INFO("Bundle contains one-time pre-key, starting generation of initial message");
                    HKDF<SHA512> hkdf;
                    uint8_t ephermalPrivKey[32] = {0};
                    uint8_t ephermalPubKey[32] = {0};
                    uint8_t DH1[32] = {0};
                    uint8_t DH2[32] = {0};
                    uint8_t DH3[32] = {0};
                    uint8_t DH4[32] = {0};
                    uint8_t AD[64] = {0};
                    uint8_t KM[160] = {0};
                    uint8_t SK[32] = {0};
                    uint8_t futureSecret[32] = {0};
                    uint8_t nonceExtra[4] = {0};
                    Curve25519::dh1(ephermalPubKey, ephermalPrivKey);
                    memcpy(DH1, decoded->signed_pre_key, 32);
                    memcpy(DH2, decoded->identity_key, 32);
                    memcpy(DH3, decoded->signed_pre_key, 32);
                    memcpy(DH4, decoded->one_time_pre_key.key, 32);
                    memcpy(AD, x3dhDB.identity_key, 32);
                    memcpy(AD + 32, &mp.public_key, 32);
                    memcpy(KM, HASH_PADDING, 32);
                    CryptRNG.rand(futureSecret, 32);
                    CryptRNG.rand(nonceExtra, 4);
                    if (!crypto->setDHPublicKey(DH1)) {
                        x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                        break;
                    } else {
                        memcpy(KM + 32, DH1, 32);
                        clean(DH1);
                    }
                    if (!Curve25519::dh2(DH2, ephermalPrivKey)) {
                        x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                        break;
                    } else {
                        memcpy(KM + 64, DH2, 32);
                        clean(DH2);
                    }
                    if (!Curve25519::dh2(DH3, ephermalPrivKey)) {
                        x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                        break;
                    } else {
                        memcpy(KM + 96, DH3, 32);
                        clean(DH3);
                    }
                    if (!Curve25519::dh2(DH4, ephermalPrivKey)) {
                        x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                        break;
                    } else {
                        memcpy(KM + 128, DH4, 32);
                        clean(DH4);
                    }
                    hkdf.setKey(KM, sizeof(KM));
                    hkdf.extract(SK, 32, x3dhHkdfInfo, sizeof(x3dhHkdfInfo));
                    hkdf.clear();
                    clean(KM);
                    uint8_t nonce[16] = {0};
                    hkdf.setKey(nonceExtra, 4);
                    hkdf.extract(nonce, 16, x3dhHkdfInfo, sizeof(x3dhHkdfInfo));
                    hkdf.clear();
                    clean(nonceExtra);
                    uint8_t cyphertext[40] = {0};
                    if (aes_ccm_ae(SK, 32, nonce, 8, futureSecret, 32, AD, 64, cyphertext, cyphertext + 32)) {
                        x3dhReply.otpk_id = decoded->one_time_pre_key.id;
                        memcpy(x3dhReply.ephermal_key, ephermalPubKey, 32);
                        memcpy(x3dhReply.initial_cyphertext.bytes, cyphertext, 40);
                        nodeInfo->x3dh_state = meshtastic_X3DHState_INIT_SENT;
                        LOG_INFO("Initial message sent to node %s", decoded->node_num);
                        printBytes("Plaintext key: ", futureSecret, 32);
                        printBytes("Encrypted key: ", cyphertext, 40);
                    } else {
                        LOG_WARN("Authenticated encryption of initial message failed, aborting X3DH handshake");
                        x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                        to = decoded->node_num;
                        // Reset state so we can try again
                        nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                    }
                    clean(futureSecret);
                    clean(SK);
                    clean(nonce);
                    clean(cyphertext);
                    clean(ephermalPrivKey);
                    clean(ephermalPubKey);
                } else {
                    LOG_WARN("No one-time pre-key provided, aborting X3DH handshake");
                    x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                    to = decoded->node_num;
                    // Reset state so we can try again
                    nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                }
            } else {
                LOG_WARN("Node public key mismatch, aborting X3DH handshake");
                x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                to = decoded->node_num;
                // Reset state so we can try again
                nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
            }
            if (to != mp.from) {
                LOG_INFO("Received key bundle from external server, sending intial message directly to node");
                auto x3dhMessage = allocDataProtobuf(x3dhReply);
                x3dhMessage->pki_encrypted = true;
                memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
                x3dhMessage->to = to;
                service->sendToMesh(x3dhMessage);
                x3dhReply = meshtastic_X3DHMessage_init_default;
            }
            break;
        }

        case meshtastic_X3DHMessageType_INITIAL_MESSAGE: {
            LOG_INFO("Initial message received, starting generation for initial secret");
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
            HKDF<SHA512> hkdf;
            uint8_t DH1[32] = {0};
            uint8_t DH2[32] = {0};
            uint8_t DH3[32] = {0};
            uint8_t DH4[32] = {0};
            uint8_t AD[64] = {0};
            uint8_t KM[160] = {0};
            uint8_t SK[32] = {0};
            memcpy(DH1, &mp.public_key, 32);
            memcpy(DH2, decoded->ephermal_key, 32);
            memcpy(DH3, decoded->ephermal_key, 32);
            memcpy(DH4, decoded->ephermal_key, 32);
            memcpy(AD, &mp.public_key, 32);
            memcpy(AD + 32, x3dhDB.identity_key, 32);
            memcpy(KM, HASH_PADDING, 32);
            if (!Curve25519::dh2(DH1, x3dhDB.signed_pre_key)) {
                x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
            } else {
                memcpy(KM + 32, DH1, 32);
                clean(DH1);
            }
            if (!crypto->setDHPublicKey(DH2)) {
                x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
            } else {
                memcpy(KM + 64, DH2, 32);
                clean(DH2);
            }
            if (!Curve25519::dh2(DH3, x3dhDB.signed_pre_key)) {
                x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
            } else {
                memcpy(KM + 96, DH3, 32);
                clean(DH3);
            }
            uint8_t otpkPrivKey = {0};
            getAndRegenOTPK(&decoded->otpk_id, &otpkPrivKey);
            if (&otpkPrivKey == ZERO) {
                x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
            }
            if (!Curve25519::dh2(DH4, &otpkPrivKey)) {
                x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
            } else {
                memcpy(KM + 128, DH4, 32);
                clean(DH4);
            }
            if (x3dhReply.type == meshtastic_X3DHMessageType_X3DH_ERROR) {
                LOG_WARN("Error in generating input for key derivation, aborting X3DH-agreement");
                nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                break;
            }
            hkdf.setKey(KM, sizeof(KM));
            hkdf.extract(SK, 32, x3dhHkdfInfo, sizeof(x3dhHkdfInfo));
            hkdf.clear();
            clean(KM);
            uint8_t nonce[16] = {0};
            hkdf.setKey(&mp.channel, 4);
            hkdf.extract(nonce, 16, x3dhHkdfInfo, sizeof(x3dhHkdfInfo));
            hkdf.clear();
            uint8_t receivedSecret[32] = {0};
            uint8_t authTag[8] = {0};
            memcpy(authTag, &decoded->initial_cyphertext.bytes + decoded->initial_cyphertext.size - 8, 8);
            if (aes_ccm_ad(SK, 32, nonce, 8, decoded->initial_cyphertext.bytes, decoded->initial_cyphertext.size - 8, AD, 64,
                           authTag, receivedSecret)) {

                memcpy(nodeInfo->x3dh_shared_key, receivedSecret, 32);
                printBytes("Plaintext key: ", receivedSecret, 32);
                printBytes("Encrypted key: ", decoded->initial_cyphertext.bytes, 40);
                nodeInfo->x3dh_state = meshtastic_X3DHState_PROTOCOL_SET;
                node->bitfield |= NODEINFO_BITFIELD_USES_X3DH_MASK;
                x3dhReply.type = meshtastic_X3DHMessageType_PROTOCOL_SWITCH;
                x3dhReply.continue_protocol = meshtastic_X3DHProtocol_X3DH_SECRET;
                LOG_INFO("X3DH-Agreement with node %s completed", node->num);
            } else {
                x3dhReply.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                LOG_WARN("Decryption unsuccessful, aborting X3dh-agreement with node %s", node->num);
            }
            clean(SK);
            clean(receivedSecret);
            clean(authTag);
            break;
        }

        case meshtastic_X3DHMessageType_PROTOCOL_SWITCH: {
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.from);
            if (nodeInfo->x3dh_state == meshtastic_X3DHState_INIT_SENT) {
                LOG_INFO("Confirmed usage of X3DH-Secret for future direct messages with node %s", mp.from);
                node->bitfield |= NODEINFO_BITFIELD_USES_X3DH_MASK;
                nodeInfo->x3dh_state = meshtastic_X3DHState_PROTOCOL_SET;
            } else if (nodeInfo->x3dh_state == meshtastic_X3DHState_PROTOCOL_SET) {
                LOG_INFO("Post-X3DH-Protocol already set, no change");
            } else {
                LOG_INFO("X3DH-Agreement not finished, protocol won't be set");
            }
            break;
        }

        case meshtastic_X3DHMessageType_X3DH_ERROR: {
            LOG_WARN("Received X3DH error from node %0x", mp.from);
            if (nodeInfo->x3dh_state == meshtastic_X3DHState_PROTOCOL_SET) {
                LOG_WARN("Node already uses post-X3DH-protocol, misguided packet or possible attack");
            } else if (decoded->node_num != 0) {
                nodeInfo = getOrCreateNodeStateEntry(decoded->node_num);
                LOG_WARN("Retrieval of pre-key-bundle of node %0x failed, aborting X3DH-Handshake", decoded->node_num);
                nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
                meshtastic_X3DHMessage init = meshtastic_X3DHMessage_init_default;
                init.type = meshtastic_X3DHMessageType_X3DH_ERROR;
                auto x3dhMessage = allocDataProtobuf(init);
                x3dhMessage->pki_encrypted = true;
                memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
                x3dhMessage->to = decoded->node_num;
                service->sendToMesh(x3dhMessage);
            } else {
                LOG_WARN("X3DH-agreement not finished, aborting handshake");
                nodeInfo->x3dh_state = meshtastic_X3DHState_X3DH_NOT_STARTED;
            }
            break;
        }

        default: {
            break;
        }
        }
        toReturn = true;
    }
    return toReturn;
}

meshtastic_MeshPacket *X3dhModule::allocReply()
{
    if (x3dhReply.type != meshtastic_X3DHMessageType_NOT_SET) {
        auto x3dhMessage = allocDataProtobuf(x3dhReply);
        x3dhMessage->decoded.portnum = ourPortNum;
        memcpy(x3dhMessage->public_key.bytes, crypto->public_key, x3dhMessage->public_key.size);
        x3dhMessage->pki_encrypted = true;
        return x3dhMessage;
    } else {
        return NULL;
    }
}

void X3dhModule::loadX3dhDb()
{
    LOG_INFO("Loading X3DH-Database from file %s", x3dhDatabaseFilename);
    LOG_INFO("Calculated size: %d", getMaxPreKeyBundleAllocatedSize());
    if (nodeDB->loadProto(x3dhDatabaseFilename, getMaxPreKeyBundleAllocatedSize(), sizeof(meshtastic_PreKeyStorage),
                          &meshtastic_PreKeyStorage_msg, &x3dhDB) != LoadFileResult::LOAD_SUCCESS) {
        LOG_WARN("Could not load X3DH-DB from disk, creating new one");
        initX3dhDb();
    } else {
        size_t preKeyBundleDatabaseSize;
        pb_get_encoded_size(&preKeyBundleDatabaseSize, meshtastic_PreKeyStorage_fields, &x3dhDB);
        LOG_INFO("Real size: %d", preKeyBundleDatabaseSize);
        LOG_INFO("Vector size: %d", x3dhDB.one_time_pre_keys.size());
        LOG_INFO("Vector max size: %d", x3dhDB.one_time_pre_keys.max_size());
    }
    if (!memcmp(x3dhDB.identity_key, ZERO, 32) || !memcmp(x3dhDB.one_time_pre_keys.at(0).key, ZERO, 32)) {
        LOG_WARN("Database corrupted, re-initializing DB");
        printBytes("Saved otpk: ", x3dhDB.one_time_pre_keys.at(0).key, 32);
        initX3dhDb();
    } else {
        otpks = &x3dhDB.one_time_pre_keys;
    }
}

void X3dhModule::loadX3dhStateDB()
{
    LOG_INFO("Loading X3DH-Node-State-DB from file %s", x3dhNodeStateDatabaseFilename);
    LOG_INFO("Calculated size: %d", getMaxStateDbAllocatedSize());
    if (nodeDB->loadProto(x3dhNodeStateDatabaseFilename, getMaxStateDbAllocatedSize(), sizeof(meshtastic_X3DHStateDB),
                          &meshtastic_X3DHStateDB_msg, &x3dhStateDb) != LoadFileResult::LOAD_SUCCESS) {
        LOG_WARN("Could not load X3DH-Node-State-DB from disk, creating new one");
        initX3dhNodeStateDb();
    } else {
        size_t StateDbBundleDatabaseSize;
        pb_get_encoded_size(&StateDbBundleDatabaseSize, meshtastic_X3DHStateDB_fields, &x3dhStateDb);
        LOG_INFO("Real size: %d", StateDbBundleDatabaseSize);
        LOG_INFO("Vector size: %d", x3dhStateDb.node_info.size());
        LOG_INFO("Vector max size: %d", x3dhStateDb.node_info.max_size());
        LOG_INFO("Node counts: %d", x3dhStateDb.node_count);
        states = &x3dhStateDb.node_info;
    }
}

void X3dhModule::initX3dhDb()
{
    LOG_DEBUG("Installing default X3DH-Database");
    memcpy(x3dhDB.identity_key, crypto->public_key, 32);
    uint8_t tempPrivKey[32] = {0};
    uint8_t tempPubKey[32] = {0};
    Curve25519::dh1(tempPubKey, tempPrivKey);
    memcpy(x3dhDB.signed_pre_key, tempPrivKey, 32);
    uint8_t tempSig[64] = {0};
    crypto->xeddsa_sign(tempPubKey, 32, tempSig);
    memcpy(x3dhDB.pre_key_signature, tempSig, 64);
    x3dhDB.one_time_pre_keys = std::vector<meshtastic_OneTimePreKey>(MAX_NUM_OTPKS);
    otpks = &x3dhDB.one_time_pre_keys;
    for (size_t i = 0; i < MAX_NUM_OTPKS; i++) {
        genOTPK(&otpks->at(i));
    }
    clean(tempPrivKey);
    clean(tempPubKey);
    clean(tempSig);
    printBytes("Identity key: ", x3dhDB.identity_key, 32);
    printBytes("Signed pre key: ", x3dhDB.signed_pre_key, 32);
    for (auto i = x3dhDB.one_time_pre_keys.begin(); i != x3dhDB.one_time_pre_keys.end(); i++) {
        auto current = *i;
        LOG_DEBUG("OTPK ID: %d", current.id);
    }
    bool result = saveX3dhDatabaseToDisk();
}

void X3dhModule::initX3dhNodeStateDb()
{
    LOG_DEBUG("Installing default X3DH-Node-State-DB");
    x3dhStateDb.node_info = std::vector<meshtastic_X3DHNodeInfo>(MAX_NUM_NODES);
    states = &x3dhStateDb.node_info;
    for (int i = 1; i < nodeDB->numMeshNodes; i++) {
        states->at(i).node_num = nodeDB->meshNodes->at(i).num;
        x3dhStateDb.node_count++;
    }

    saveX3dhNodeStateDatabaseToDisk();
}

void X3dhModule::genOTPK(meshtastic_OneTimePreKey *otpk)
{
    uint8_t tempPubKey[32] = {0};
    Curve25519::dh1(tempPubKey, otpk->key);
    otpk->id = x3dhRandom();
    clean(tempPubKey);
}

void X3dhModule::getAndRegenOTPK(uint32_t *keyId, uint8_t otpkPrivKey[32])
{
    for (auto iterator = otpks->begin(); iterator != otpks->end(); ++iterator) {
        meshtastic_OneTimePreKey tempOtpks = *iterator;
        if (&tempOtpks.id == keyId) {
            memcpy(otpkPrivKey, tempOtpks.key, 32);
            otpks->erase(iterator);
            if (x3dhDB.node_num ==
                myNodeInfo.my_node_num) { // Only regenerate one-time pre-key if we don't store bundle on external server
                meshtastic_OneTimePreKey otpk = meshtastic_OneTimePreKey_init_default;
                genOTPK(&otpk);
                otpks->insert(iterator, otpk);
            }
        }
    }
}

size_t X3dhModule::getMaxPreKeyBundleAllocatedSize()
{
    meshtastic_PreKeyStorage emptyPreKeyStorage;
    size_t preKeyBundleDatabaseSize;
    pb_get_encoded_size(&preKeyBundleDatabaseSize, meshtastic_PreKeyStorage_fields, &emptyPreKeyStorage);
    return preKeyBundleDatabaseSize + (MAX_NUM_OTPKS * meshtastic_OneTimePreKey_size);
}

size_t X3dhModule::getMaxStateDbAllocatedSize()
{
    meshtastic_X3DHStateDB emptyStateDb;
    emptyStateDb.node_count = nodeDB->meshNodes->size();
    size_t stateDatabaseSize;
    pb_get_encoded_size(&stateDatabaseSize, meshtastic_X3DHStateDB_fields, &emptyStateDb);
    return stateDatabaseSize + (MAX_NUM_NODES * meshtastic_X3DHNodeInfo_size);
}

bool X3dhModule::checkDatabaseExists()
{
    spiLock->lock();
    bool x3dhDatabaseExists = FSCom.exists(x3dhDatabaseFilename);
    spiLock->unlock();
    return x3dhDatabaseExists;
}

bool X3dhModule::checkStateDatabaseExists()
{
    spiLock->lock();
    bool x3dhStateDatabaseExists = FSCom.exists(x3dhNodeStateDatabaseFilename);
    spiLock->unlock();
    return x3dhStateDatabaseExists;
}

bool X3dhModule::saveX3dhDatabaseToDisk()
{
    size_t preKeyBundleDatabaseSize;
    pb_get_encoded_size(&preKeyBundleDatabaseSize, meshtastic_PreKeyStorage_fields, &x3dhDB);
    LOG_INFO("X3DH-DB size before saving: %d", preKeyBundleDatabaseSize);
    return nodeDB->saveProto(x3dhDatabaseFilename, preKeyBundleDatabaseSize, &meshtastic_PreKeyStorage_msg, &x3dhDB, false);
}

bool X3dhModule::saveX3dhNodeStateDatabaseToDisk()
{
    size_t nodeStateDatabaseSize;
    pb_get_encoded_size(&nodeStateDatabaseSize, meshtastic_X3DHStateDB_fields, &x3dhStateDb);
    LOG_INFO("X3DH-Nodeinfo-DB size before saving: %d", nodeStateDatabaseSize);
    return nodeDB->saveProto(x3dhNodeStateDatabaseFilename, nodeStateDatabaseSize, &meshtastic_X3DHStateDB_msg, &x3dhStateDb,
                             false);
}

meshtastic_X3DHNodeInfo *X3dhModule::getOrCreateNodeStateEntry(NodeNum num)
{
    meshtastic_X3DHNodeInfo *nodeInfo = NULL;
    for (auto i = states->begin(); i != states->end(); i++) {
        meshtastic_X3DHNodeInfo current = *i;
        if (current.node_num == num) {
            nodeInfo = &current;
        }
    }
    if (nodeInfo == NULL && x3dhStateDb.node_count < MAX_NUM_NODES) {
        meshtastic_X3DHNodeInfo newNode = meshtastic_X3DHNodeInfo_init_default;
        newNode.node_num = num;
        states->insert(states->end(), newNode);
        nodeInfo = &states->at(x3dhStateDb.node_count);
        x3dhStateDb.node_count++;
        nodeInfo = &*states->end();
    }
    return nodeInfo;
}

bool meshtastic_PreKeyStorage_callback(pb_istream_t *istream, pb_ostream_t *ostream, const pb_field_iter_t *field)
{
    if (ostream) {
        std::vector<meshtastic_OneTimePreKey> const *vec = (std::vector<meshtastic_OneTimePreKey> *)field->pData;
        for (auto item : *vec) {
            if (!pb_encode_tag_for_field(ostream, field))
                return false;
            pb_encode_submessage(ostream, meshtastic_OneTimePreKey_fields, &item);
        }
    }
    if (istream) {
        meshtastic_OneTimePreKey otpk; // this gets good data
        std::vector<meshtastic_OneTimePreKey> *vec = (std::vector<meshtastic_OneTimePreKey> *)field->pData;

        if (istream->bytes_left && pb_decode(istream, meshtastic_OneTimePreKey_fields, &otpk))
            vec->push_back(otpk);
    }
    return true;
}

bool meshtastic_X3DHStateDB_callback(pb_istream_t *istream, pb_ostream_t *ostream, const pb_field_iter_t *field)
{
    if (ostream) {
        std::vector<meshtastic_X3DHNodeInfo> const *vec = (std::vector<meshtastic_X3DHNodeInfo> *)field->pData;
        for (auto item : *vec) {
            if (!pb_encode_tag_for_field(ostream, field))
                return false;
            pb_encode_submessage(ostream, meshtastic_X3DHNodeInfo_fields, &item);
        }
    }
    if (istream) {
        meshtastic_X3DHNodeInfo nodeInfo; // this gets good data
        std::vector<meshtastic_X3DHNodeInfo> *vec = (std::vector<meshtastic_X3DHNodeInfo> *)field->pData;

        if (istream->bytes_left && pb_decode(istream, meshtastic_X3DHNodeInfo_fields, &nodeInfo))
            vec->push_back(nodeInfo);
    }
    return true;
}