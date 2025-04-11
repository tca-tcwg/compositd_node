# CC系统GPU节点

## 使用说明
通过`bin/start.sh`即可运行，其会在后台运行tpm模拟器并在前台运行`gpu-httpd`。

## 接口说明

1. /ping  
方法: GET  
返回值: "pong"

2. /information  
方法: GET  
返回值: 度量结果与TPM信息
```json
{
    "ak_pubkey":{
        "tpm": {
            "x_point": "86b00d6a7b9c6c438b38f955324778607e409e103f02312f3c97d2c4ca1c990d",
            "x_size": 64,
            "y_point": "841c0a6115d4b156bcb6dd295a20572d9c2d54ec083981cb91155e7e45b36f91",
            "y_size": 64
        }
    },
    "data": {
        "tpm" : {
            "measurement" : {
                "time-stamp" : "2024.12.06 02:41:06",
                "measurement":[
                {"name":"/usr/local/cuda/version.json","hash":"d82d44b06b0cf7f4177191e5f057a21c222d099f6de7794940dbb57157ee9cfb","type":"config file","size":"2.87K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/tokenizer_config.json","hash":"c32ce8035a2a5c139b4259800fccb4d59736e70e3964529cfab7c2fa99e940ec","type":"config file","size":"244B"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/tokenizer.model","hash":"4f70371c98d9282761b1728a398d04d8766e40b7d97344356c26135c1878618b","type":"script file","size":"994.50K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/tokenization_chatglm.py","hash":"38f1ec0a3d8ae1c4ce99b090a24724b92051490593efbfacb049cbe915e61c40","type":"script file","size":"11.01K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/quantization.py","hash":"a98ec1e9a81b191cb502bcb62577a740e1e382a320ecd578680aa934afa06b7f","type":"script file","size":"14.35K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/pytorch_model.bin.index.json","hash":"46adb191db7db51730f65f21f7e157df71db23e68b53c83e771ebee2e2e8e21d","type":"config file","size":"19.96K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/pytorch_model-00007-of-00007.bin","hash":"4925889f0bd84ff32db51c2eefdf6c6ce7b314879c6aa5275422c2e58c6c96db","type":"binary file","size":"0.98G"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/pytorch_model-00006-of-00007.bin","hash":"9d1861f1b80d9550a84e1b612d61ba4fd87306a71daad784478fb2935d119a6d","type":"binary file","size":"1.80G"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/pytorch_model-00005-of-00007.bin","hash":"2e11b664234779890bcf11d7605e9586cd3d99c669019a5bf898a0332d698e85","type":"binary file","size":"1.83G"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/pytorch_model-00004-of-00007.bin","hash":"8d971c6c8b6ef7cf381b09b20581f7136dd08ff3ca1c39791ebc766a4f8523b8","type":"binary file","size":"1.69G"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/pytorch_model-00003-of-00007.bin","hash":"51e0585209755931b45fa85f60760cb3f0dbda67f8311a62591b1f64789d823f","type":"binary file","size":"1.80G"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/pytorch_model-00002-of-00007.bin","hash":"b8b5fd987453a18950d62dd933743ab76bf01198f08997e5f52a4732f67a9d63","type":"binary file","size":"1.83G"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/pytorch_model-00001-of-00007.bin","hash":"19f62f6136ae6eae436d9d2a932dec0347112cd8b2c6fd03e963602c744fb04b","type":"binary file","size":"1.70G"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/modeling_chatglm.py","hash":"e1fbb90052a0502567a681e879088de5208afe09c635beca4df76af6f7332b58","type":"script file","size":"54.29K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/configuration_chatglm.py","hash":"94049104fa3ebbdad386e7cc1ed61d378db7aecb83771a21efbd7be132be05dd","type":"script file","size":"2.28K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/configuration.json","hash":"0355b097e8a69a001f0dc93910a9da547fbdfc06e02b0197e20b536992f49381","type":"config file","size":"40B"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/config.json","hash":"7da4d51fff92e0261cab62b098eee14c55c77a8c31627faf47ea8419e85f2416","type":"config file","size":"1.29K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/README.md","hash":"ebdd01fdf0077b974a3d177bb9b45482a97fbd77b52ace5cc5d8fa65ec6b72bb","type":"text file","size":"4.37K"},
                {"name":"/home/tcwg/.cache/modelscope/hub/ZhipuAI/chatglm3-6b/MODEL_LICENSE","hash":"3849d34ae825c68d09127e358502988f957a9bb8f35d9c1c11a15a8ecfd2b2ef","type":"unknown type","size":"4.04K"}],
                "total_hash" : "a2851cbf468fae1a2abb6937827696b1b05bb64e620876c1067b1f2f80a7a9a2"
            },
            "ek_pub": {
                "x_point": "78d926c582566a70eedffcda4fe147e1b24fe624305441167fac483a3079b2e7",
                "x_size": 64,
                "y_point": "8bdc62992c3382e29687114ea0a9e1ac69f91283ae1d018b6d37859731617c3a",
                "y_size": 64
            },
            "ekcert": "308203163082029ba00302010202141526b1cb8f1e374d8d59b35955392f0d49dbee47300a06082a8648ce3d0403033078310b300906035504061302434e3121301f060355040a0c184e6174696f6e7a20546563686e6f6c6f6769657320496e63311b3019060355040b0c124e6174696f6e7a2054504d204465766963653129302706035504030c204e6174696f6e7a2054504d204d616e75666163747572696e6720434120303031301e170d3232303732303030303030305a170d3337303732303030303030305a30003059301306072a8648ce3d020106082a8648ce3d0301070342000426263588971ef42c4e1ccf6d799e75e5dfc57caa79a3929139c56dda4bb4a0a6b2943fd697132cf1ded596255f1bac938fcec5d2a091254311cbe5a7b91d0354a382017930820175304f06082b0601050507010104433041303f06082b060105050730028633687474703a2f2f706b692e6e6174696f6e7a2e636f6d2e636e2f456b4d667243413030312f456b4d667243413030312e63727430440603551d1f043d303b3039a037a0358633687474703a2f2f706b692e6e6174696f6e7a2e636f6d2e636e2f456b4d667243413030312f456b4d667243413030312e63726c301f0603551d23041830168014022cbeed5d77060f2833e9d5376ba8bc308cd9ba30140603551d20040d300b300906072a811ccf55040330100603551d25040930070605678105080130210603551d09041a3018301606056781050210310d300b0c03322e30020100020174300e0603551d0f0101ff04040302052030520603551d110101ff04483046a444304231163014060567810502010c0b69643a344535343541303031143012060567810502020c095a333248333330544331123010060567810502030c0769643a30373535300c0603551d130101ff04023000300a06082a8648ce3d040303036900306602310082be3b367ea51c0317c195f6285edb1f7e6e436c514470d28f9f051266f31b4a7d050235738945ec4497eb650ae90883023100a6ea8da753d0b792ccf026b7d3a052ba3edf51b70a9c20fa16b54f03609d82ca6b7c622970e817c5a20703348d1edf5f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "ekcert_size": 1000,
            "sequence": "1.62",
            "tpm_id": "xCGfTPM",
            "tpm_version": "2.0"
        }
    }
}

```
3. /quote  
方法: POST  
请求示例:  
```json
{
    "nonce" : "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "nonce_size" : 32,
    "mask" : "0000000000000000000000000000000000000000000000000000000000000000"
}
```
返回值:
```json
{
    "status" : 0,
    "evidence" : {
        "quote_tpm" : "base64 encoded TPM quote",
        "quote_size" : 0 // lenth of base64 encoded TPM quote
    },
    "measurement" : {
        ... // return value of information interface
    }
}
```
status代码:
```C
#define RC_SUCCESS 0 // 成功执行的返回值
#define RC_GPU_MEASUTE_FAIL 9001 // 获取度量结果失败
#define RC_REQUEST_ERROR 9002 // POST 请求错误
#define RC_TPM_QUOTE_FAIL 9003 // TPM quote 失败

```

# 配置信息
默认监听端口8080，度量文件列表在config/measurement-list下配置。
每行只能写一个文件名，支持正则表达式。