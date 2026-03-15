#include "crow_all.h"
#include "Server.h"
#include "User.h"
#include "BioModule.h"
#include "SecureRecordLayer.h"
#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <sstream>
#include <iomanip>

// --- Base64 与 Hex 工具 ---
std::string Base64Encode(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) return "";
    std::vector<uint8_t> encoded(4 * ((buffer.size() + 2) / 3) + 1);
    int len = EVP_EncodeBlock(encoded.data(), buffer.data(), buffer.size());
    return std::string(encoded.begin(), encoded.begin() + len);
}

std::vector<uint8_t> Base64Decode(const std::string& input) {
    if (input.empty()) return {};
    std::vector<uint8_t> decoded(input.size());
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);
    int outl = 0, totall = 0;
    if (EVP_DecodeUpdate(ctx, decoded.data(), &outl, reinterpret_cast<const uint8_t*>(input.data()), input.size()) < 0) {
        EVP_ENCODE_CTX_free(ctx); return {};
    }
    totall = outl;
    if (EVP_DecodeFinal(ctx, decoded.data() + outl, &outl) < 0) {
        EVP_ENCODE_CTX_free(ctx); return {};
    }
    totall += outl;
    decoded.resize(totall);
    EVP_ENCODE_CTX_free(ctx);
    return decoded;
}

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (unsigned char b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ========================================================
// 核心状态机与大屏监控广播通道
// ========================================================
Server gateway;
std::unique_ptr<User> virtualDevice = nullptr;

// 监控大屏的 WebSocket 连接池
std::unordered_set<crow::websocket::connection*> monitor_connections;
std::mutex monitor_mtx;
std::unordered_set<crow::websocket::connection*> device_connections;
std::mutex device_mtx;

void BroadcastToMonitor(const std::string& event, const std::string& title, const std::string& details) {
    crow::json::wvalue msg;
    msg["event"] = event;
    msg["title"] = title;
    msg["details"] = details;
    std::string dump = msg.dump();
    
    std::lock_guard<std::mutex> lock(monitor_mtx);
    for (auto* conn : monitor_connections) {
        conn->send_text(dump);
    }
}

int main() {
    crow::SimpleApp app;
    gateway.ClearDatabase(); 

    // API 1: 重置网关数据库
    CROW_ROUTE(app, "/api/reset").methods("POST"_method, "OPTIONS"_method)([&](const crow::request& req){
        // 1. 处理浏览器的 CORS 跨域预检请求
        if (req.method == crow::HTTPMethod::OPTIONS) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }

        try {
            // 2. 执行核心清理逻辑
            gateway.ClearDatabase();

            BroadcastToMonitor("system", "系统重置", "数据库与所有安全凭证已被清空");
            
            // 3. 向所有在线的 Android 设备广播“强制踢下线”指令
            std::lock_guard<std::mutex> lock(device_mtx);
            for (auto* conn : device_connections) {
                conn->send_text("{\"type\": \"system_reset\"}");
            }
            
            // 4. 返回成功，并附带跨域头
            crow::response res(200, "{\"status\":\"success\"}");
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        } catch (const std::exception& e) {
            crow::response res(500, e.what());
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // API 2: 注册
    CROW_ROUTE(app, "/api/register").methods("POST"_method)([&](const crow::request& req){
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        try {
            std::string uid = body["uid"].s();
            std::string pkSigStr = body["avk_pkSig"].s();
            std::string skEncStr = body["avk_skEnc"].s();

            // ==========================================
            // 【新增】：向大屏广播完整的注册凭证
            // ==========================================
            std::string auditMsg = "【设备 UID】: " + uid + "\n\n";
            auditMsg += "【签名公钥 pk_Sig】:\n" + pkSigStr + "\n\n";
            auditMsg += "【解密密钥 sk_Enc】:\n" + skEncStr;
            BroadcastToMonitor("crypto", "📥 收到设备注册载荷", auditMsg);

            // 2. 将 Hex 字符串解码为底层的 Bytes 
            ProtocolMessages::RegistrationRequest regReq;
            regReq.uid = uid;
            
            //把 Hex 字符串转换回二进制数组塞进请求体
            regReq.avk_pkSig = HexToBytes(pkSigStr);
            regReq.avk_skEnc = HexToBytes(skEncStr);

            // 3. 将真实请求塞给网关状态机处理（签名并存入 SQLite）
            ProtocolMessages::RegistrationResponse regResp = gateway.ProcessRegistration(regReq);
            
            BroadcastToMonitor("crypto", "注册完成，下发网关凭证", "网关签名公钥(Hex): " + BytesToHex(regResp.serversigpk));

            crow::json::wvalue res;
            res["status"] = "success";
            res["serversigpk"] = Base64Encode(regResp.serversigpk);
            return crow::response(200, res);
        } catch (const std::exception& e) {
            return crow::response(500, e.what());
        }
    });

    // ==========================================
    // 新增：专供 Web Vue 大屏监听的通道
    // ==========================================
    CROW_WEBSOCKET_ROUTE(app, "/ws/monitor")
        .onopen([&](crow::websocket::connection& conn) {
            std::lock_guard<std::mutex> lock(monitor_mtx);
            monitor_connections.insert(&conn);
            std::cout << "[Monitor] Web 大屏监控已接入。\n";
        })
        .onclose([&](crow::websocket::connection& conn, const std::string& reason) {
            std::lock_guard<std::mutex> lock(monitor_mtx);
            monitor_connections.erase(&conn);
        });

    // ==========================================
    // Android 设备的真实业务通道
    // ==========================================
    CROW_WEBSOCKET_ROUTE(app, "/ws/auth")
        .onopen([&](crow::websocket::connection& conn) {
            std::lock_guard<std::mutex> lock(device_mtx);
            device_connections.insert(&conn); // 【新增】加入连接池
        })
        .onclose([&](crow::websocket::connection& conn, const std::string& reason) {
            std::lock_guard<std::mutex> lock(device_mtx);
            device_connections.erase(&conn); // 【新增】移出连接池
        })
        .onmessage([&](crow::websocket::connection& conn, const std::string& data, bool is_binary) {
            auto body = crow::json::load(data);
            if (!body) return;
            std::string msg_type = body["type"].s();

            try {
                if (msg_type == "auth_request") {
                    std::string uid = body["uid"].s();
                    BroadcastToMonitor("crypto", "收到认证请求", "开始为 UID [" + uid + "] 生成挑战参数...");

                    ProtocolMessages::AuthChallenge challenge = gateway.GenerateAuthChallenge(uid);
                    
                    std::string details = "1. 生成 ECDH 临时公钥: " + BytesToHex(challenge.dhpubS).substr(0, 40) + "...\n";
                    details += "2. 使用网关长期私钥进行 ECDSA 签名\n";
                    details += "3. 签名结果 (Hex): " + BytesToHex(challenge.serversigm).substr(0, 40) + "...";
                    BroadcastToMonitor("crypto", "下发挑战包 (Challenge)", details);

                    crow::json::wvalue step1;
                    step1["type"] = "auth_challenge";
                    step1["dhpubS"] = Base64Encode(challenge.dhpubS);
                    step1["serversigm"] = Base64Encode(challenge.serversigm);
                    conn.send_text(step1.dump());
                }
                else if (msg_type == "auth_response") {
                    std::string uid = body["uid"].s();
                    ProtocolMessages::AuthResponse authResp;
                    authResp.uid = uid;
                    authResp.tau = Base64Decode(body["tau"].s());
                    authResp.tagU = Base64Decode(body["tagU"].s());

                    BroadcastToMonitor("crypto", "收到客户端挑战响应", "收到密文包裹 tau 及认证标签 tagU。\n开始解析...");

                    ProtocolMessages::AuthConfirmation confirmation = gateway.ProcessAuthResponse(authResp);

                    if (confirmation.success) {
                        std::string skHex = BytesToHex(gateway.GetSessionKey(uid));
                        BroadcastToMonitor("success", "双向认证彻底成功", "安全层初始化完毕。\n派生出会话密钥 (SessionKey): " + skHex + "\n等待业务指令...");
                    }

                    crow::json::wvalue step3;
                    step3["type"] = "auth_confirmation";
                    step3["success"] = confirmation.success;
                    if (confirmation.success) {
                        step3["tagS"] = Base64Encode(confirmation.tagS);
                        step3["serversigtag"] = Base64Encode(confirmation.serversigtag);
                    }
                    conn.send_text(step3.dump());
                }
                else if (msg_type == "secure_command") {
                    std::string uid = body["uid"].s();
                    std::string encryptedPayloadB64 = body["command"].s();

                    BroadcastToMonitor("crypto", "📥 收到 AEAD 加密数据", "Base64密文: " + encryptedPayloadB64);

                    auto sessionIt = gateway.m_activeSessions.find(uid);
                    if (sessionIt == gateway.m_activeSessions.end()) throw std::runtime_error("Session not found");
                    AuthSession& session = sessionIt->second;

                    CryptoModule::Bytes ciphertext = Base64Decode(encryptedPayloadB64);
                    std::string plaintextCmd = session.secureLayer.UnprotectRecord(ciphertext);
                    
                    BroadcastToMonitor("success", "🔓 ChaCha20 解密与 Tag 验证通过", "解密出的原始指令: " + plaintextCmd);

                    // 通知前端动画更新
                    BroadcastToMonitor("device_sync", "执行设备指令", plaintextCmd);

                    std::string feedbackJson = "{\"status\":\"success\", \"executed_command\":" + plaintextCmd + "}";
                    CryptoModule::Bytes respCiphertext = session.secureLayer.ProtectRecord(feedbackJson);

                    BroadcastToMonitor("crypto", "📤 组装回执并加密", "准备将结果加密发回 Android...");

                    crow::json::wvalue res;
                    res["type"] = "command_result";
                    res["payload"] = Base64Encode(respCiphertext);
                    conn.send_text(res.dump());
                }
            } catch (const std::exception& e) {
                BroadcastToMonitor("error", "🛑 密码学防御机制触发", e.what());
                crow::json::wvalue err; err["type"] = "error"; err["message"] = e.what();
                conn.send_text(err.dump());
            }
        });

    app.port(8081).multithreaded().run();
    return 0;
}