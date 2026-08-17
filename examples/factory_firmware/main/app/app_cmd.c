#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_console.h"
#include "argtable3/argtable3.h"
#include "esp_event.h"
#include "esp_system.h"

#include "app_cmd.h"
#include "app_ota.h"
#include "event_loops.h"
#include "storage.h"
#include "app_device_info.h"
#include "util.h"

#include "tf.h"
#include "sensecap-watcher.h"
#include "factory_info.h"
#include "app_audio_player.h"

#include "iperf.h"
#include "app_rgb.h"

static const char *TAG = "cmd";

#define PROMPT_STR "SenseCAP"

int max(int a, int b) {
    return (a > b) ? a : b;
}

/** wifi set command **/
static struct {
    struct arg_str *ssid;
    struct arg_str *password;
    struct arg_end *end;
} wifi_cfg_args;

static int wifi_cfg_set(int argc, char **argv)
{

    struct view_data_wifi_config cfg;

    memset(&cfg, 0, sizeof(cfg));

    int nerrors = arg_parse(argc, argv, (void **) &wifi_cfg_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, wifi_cfg_args.end, argv[0]);
        return 1;
    }

    if (wifi_cfg_args.ssid->count) {
        int len = strlen( wifi_cfg_args.ssid->sval[0] );
        if( len > (sizeof(cfg.ssid) - 1) ) { 
            ESP_LOGE(TAG,  "out of 31 bytes :%s", wifi_cfg_args.ssid->sval[0]);
            return -1;
        }
        strncpy( cfg.ssid, wifi_cfg_args.ssid->sval[0], len );
    } else {
        ESP_LOGE(TAG,  "no ssid");
        return -1;
    }

    if (wifi_cfg_args.password->count) {
        int len = strlen(wifi_cfg_args.password->sval[0]);
        if( len > (sizeof(cfg.password) - 1) ){ 
            ESP_LOGE(TAG,  "out of 64 bytes :%s", wifi_cfg_args.password->sval[0]);
            return -1;
        }
        cfg.have_password = true;
        strncpy( cfg.password, wifi_cfg_args.password->sval[0], len );
    }
    esp_event_post_to(app_event_loop_handle, VIEW_EVENT_BASE, VIEW_EVENT_WIFI_CONNECT, &cfg, sizeof(struct view_data_wifi_config), pdMS_TO_TICKS(10000));
    return 0;
}
//wifi_cfg -s ssid -p password
static void register_cmd_wifi_sta(void)
{
    wifi_cfg_args.ssid =  arg_str0("s", NULL, "<ssid>", "SSID of AP");
    wifi_cfg_args.password =  arg_str0("p", NULL, "<password>", "password of AP");
    wifi_cfg_args.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "wifi_sta",
        .help = "WiFi is station mode, join specified soft-AP",
        .hint = NULL,
        .func = &wifi_cfg_set,
        .argtable = &wifi_cfg_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/************* iperf **************/
typedef struct {
    struct arg_str *ip;
    struct arg_lit *server;
    struct arg_lit *udp;
    struct arg_lit *version;
    struct arg_int *port;
    struct arg_int *length;
    struct arg_int *interval;
    struct arg_int *time;
    struct arg_int *bw_limit;
    struct arg_lit *abort;
    struct arg_end *end;
} wifi_iperf_t;
static wifi_iperf_t iperf_args;

static int wifi_cmd_iperf(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &iperf_args);
    iperf_cfg_t cfg;

    if (nerrors != 0) {
        arg_print_errors(stderr, iperf_args.end, argv[0]);
        return 0;
    }

    memset(&cfg, 0, sizeof(cfg));

    // now wifi iperf only support IPV4 address
    cfg.type = IPERF_IP_TYPE_IPV4;

    if ( iperf_args.abort->count != 0) {
        iperf_stop();
        return 0;
    }

    if ( ((iperf_args.ip->count == 0) && (iperf_args.server->count == 0)) ||
            ((iperf_args.ip->count != 0) && (iperf_args.server->count != 0)) ) {
        ESP_LOGE(TAG, "should specific client/server mode");
        return 0;
    }

    if (iperf_args.ip->count == 0) {
        cfg.flag |= IPERF_FLAG_SERVER;
    } else {
        cfg.destination_ip4 = esp_ip4addr_aton(iperf_args.ip->sval[0]);
        cfg.flag |= IPERF_FLAG_CLIENT;
    }

    // cfg.source_ip4 = wifi_get_local_ip();
    // if (cfg.source_ip4 == 0) {
    //     return 0;
    // }

    if (iperf_args.udp->count == 0) {
        cfg.flag |= IPERF_FLAG_TCP;
    } else {
        cfg.flag |= IPERF_FLAG_UDP;
    }

    if (iperf_args.length->count == 0) {
        cfg.len_send_buf = 0;
    } else {
        cfg.len_send_buf = iperf_args.length->ival[0];
    }

    if (iperf_args.port->count == 0) {
        cfg.sport = IPERF_DEFAULT_PORT;
        cfg.dport = IPERF_DEFAULT_PORT;
    } else {
        if (cfg.flag & IPERF_FLAG_SERVER) {
            cfg.sport = iperf_args.port->ival[0];
            cfg.dport = IPERF_DEFAULT_PORT;
        } else {
            cfg.sport = IPERF_DEFAULT_PORT;
            cfg.dport = iperf_args.port->ival[0];
        }
    }

    if (iperf_args.interval->count == 0) {
        cfg.interval = IPERF_DEFAULT_INTERVAL;
    } else {
        cfg.interval = iperf_args.interval->ival[0];
        if (cfg.interval <= 0) {
            cfg.interval = IPERF_DEFAULT_INTERVAL;
        }
    }

    if (iperf_args.time->count == 0) {
        cfg.time = IPERF_DEFAULT_TIME;
    } else {
        cfg.time = iperf_args.time->ival[0];
        if (cfg.time <= cfg.interval) {
            cfg.time = cfg.interval;
        }
    }

    /* iperf -b */
    if (iperf_args.bw_limit->count == 0) {
        cfg.bw_lim = IPERF_DEFAULT_NO_BW_LIMIT;
    } else {
        cfg.bw_lim = iperf_args.bw_limit->ival[0];
        if (cfg.bw_lim <= 0) {
            cfg.bw_lim = IPERF_DEFAULT_NO_BW_LIMIT;
        }
    }


    ESP_LOGI(TAG, "mode=%s-%s port:%d,\
             dip=%" PRId32 ".%" PRId32 ".%" PRId32 ".%" PRId32 ":%d,\
             interval=%" PRId32 ", time=%" PRId32 "",
             cfg.flag & IPERF_FLAG_TCP ? "tcp" : "udp",
             cfg.flag & IPERF_FLAG_SERVER ? "server" : "client", cfg.sport,
             cfg.destination_ip4 & 0xFF, (cfg.destination_ip4 >> 8) & 0xFF,
             (cfg.destination_ip4 >> 16) & 0xFF, (cfg.destination_ip4 >> 24) & 0xFF, cfg.dport,
             cfg.interval, cfg.time);

    iperf_start(&cfg);

    return 0;
}

static void register_cmd_iperf(void)
{
    iperf_args.ip = arg_str0("c", "client", "<ip>", "run in client mode, connecting to <host>");
    iperf_args.server = arg_lit0("s", "server", "run in server mode");
    iperf_args.udp = arg_lit0("u", "udp", "use UDP rather than TCP");
    iperf_args.version = arg_lit0("V", "ipv6_domain", "use IPV6 address rather than IPV4");
    iperf_args.port = arg_int0("p", "port", "<port>", "server port to listen on/connect to");
    iperf_args.length = arg_int0("l", "len", "<length>", "Set read/write buffer size");
    iperf_args.interval = arg_int0("i", "interval", "<interval>", "seconds between periodic bandwidth reports");
    iperf_args.time = arg_int0("t", "time", "<time>", "time in seconds to transmit for (default 10 secs)");
    iperf_args.bw_limit = arg_int0("b", "bandwidth", "<bandwidth>", "bandwidth to send at in Mbits/sec");
    iperf_args.abort = arg_lit0("a", "abort", "abort running iperf");
    iperf_args.end = arg_end(1);
    const esp_console_cmd_t iperf_cmd = {
        .command = "iperf",
        .help = "iperf command",
        .hint = NULL,
        .func = &wifi_cmd_iperf,
        .argtable = &iperf_args
    };

    ESP_ERROR_CHECK( esp_console_cmd_register(&iperf_cmd) );
}

/************* reboot **************/
static int do_reboot(int argc, char **argv)
{
    esp_event_post_to(app_event_loop_handle, VIEW_EVENT_BASE, VIEW_EVENT_REBOOT, NULL, 0, pdMS_TO_TICKS(10000));
    return 0;
}

static void register_cmd_reboot(void)
{
    const esp_console_cmd_t cmd = {
        .command = "reboot",
        .help = "reboot the device",
        .hint = NULL,
        .func = &do_reboot,
        .argtable = NULL
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/************* factory reset **************/
static int do_factory_reset(int argc, char **argv)
{
    set_reset_factory(false);
    return 0;
}

static void register_cmd_factory_reset(void)
{
    const esp_console_cmd_t cmd = {
        .command = "factory_reset",
        .help = "factory reset and reboot the device",
        .hint = NULL,
        .func = &do_factory_reset,
        .argtable = NULL
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}


/************* force ota **************/
static struct {
    struct arg_int *type;
    struct arg_str *url;
    struct arg_end *end;
} force_ota_args;

static int do_force_ota(int argc, char **argv)
{
    int change = 0;
    esp_err_t ret = ESP_OK;
    int type = -1;
    char *url = NULL;

    int nerrors = arg_parse(argc, argv, (void **) &force_ota_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, force_ota_args.end, argv[0]);
        return 1;
    }

    if (force_ota_args.type->count) {
        type = *(force_ota_args.type->ival);
        if( type < 0 || type > 2 ) { 
            ESP_LOGE(TAG,  "must be in range [0, 2]");
            return -1;
        }
        change = 1;
    }

    if (force_ota_args.url->count) {
        int len = strlen(force_ota_args.url->sval[0]);
        if( len < 16 ){ 
            ESP_LOGE(TAG,  "url too short");
            return -1;
        }
        change = 2;
        // url = psram_calloc(1, 256);
        // strncpy( url, force_ota_args.url->sval[0], len );
        url = force_ota_args.url->sval[0];
    }

    if( change == 2 ) {
        switch (type)
        {
        case 0:
            ESP_LOGI(TAG, "the ai model ota is blocking, please wait a while ...");
            ret = app_ota_ai_model_download(url, 0);
            break;
        case 1:
            ret = app_ota_himax_fw_download(url);
            break;
        case 2:
            app_ota_any_ignore_version_check(true);
            ret = app_ota_esp32_fw_download(url);
            break;
        
        default:
            break;
        }
        // if (url) free(url);  // we let memory leak, because we need it exist
    } else {
        ESP_LOGE(TAG, "both args must be provided");
        return -1;
    }

    if ( ret == ESP_OK ) {
        ESP_LOGI(TAG, "the ota is %s", type == 0 ? "done" : "going...");
    } else {
        ESP_LOGE(TAG, "the ota request failed, err=0x%x", ret);
    }
    
    return 0;
}

static void register_cmd_force_ota(void)
{
    force_ota_args.type =  arg_int0("t", "ota_type", "<int>", "0: ai model, 1: himax, 2: esp32");
    force_ota_args.url =  arg_str0(NULL, "url", "<string>", "url for ai model, himax or esp32 firmware");
    force_ota_args.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "ota",
        .help = "force ota, ignoring version check",
        .hint = NULL,
        .func = &do_force_ota,
        .argtable = &force_ota_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}


/************* taskflow import and export **************/
static struct {
    struct arg_lit *import;
    struct arg_lit *export;
    struct arg_str *file;
    struct arg_str *json;
    struct arg_end *end;
} taskflow_cfg_args;

static int taskflow_cmd(int argc, char **argv)
{
    bool import = false;
    bool export = false;
    bool use_sd = false;
    char file[128] = {0};
    char *p_json = NULL;
    bool used_json = false;

    memset(file, 0, sizeof(file));

    int nerrors = arg_parse(argc, argv, (void **) &taskflow_cfg_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, taskflow_cfg_args.end, argv[0]);
        return 1;
    }

    if (taskflow_cfg_args.export->count) {
        export = true;
    }

    if (taskflow_cfg_args.import->count) {
        import = true;
    }

    if ( taskflow_cfg_args.file->count ) {
        int len = strlen(taskflow_cfg_args.file->sval[0]);
        if( len > 0 ){
            use_sd = true;
            snprintf(file, sizeof(file), "/sdcard/%s", taskflow_cfg_args.file->sval[0]);
        }
    } else if( taskflow_cfg_args.json->count ) {

        printf("Please input taskflow json:\n");
        char *str = psram_malloc(102400); 
        if( fgets(str, 102400, stdin) != NULL ) {
            printf("%s\n", str);
            p_json = str;
        } else {
            free(str);
            printf("fgets fail\n");
        }
    }

    if( import ) {
        if( use_sd ) {
            FILE *fp = fopen(file, "r");
            if( fp != NULL ) {
                fseek(fp, 0, SEEK_END);
                int len = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                char *p_taskflow = psram_malloc(len+1);
                fread(p_taskflow, len, 1, fp);
                fclose(fp);
                ESP_LOGI(TAG, "taskflow import from SD success! %s", file);

                esp_event_post_to(app_event_loop_handle, CTRL_EVENT_BASE, CTRL_EVENT_TASK_FLOW_START_BY_CMD, 
                                            &p_taskflow,
                                            sizeof(void *), /* ptr size */
                                            portMAX_DELAY); 
                // tf_engine_flow_set(p_taskflow, len);
                // free(p_taskflow);
            } else {
                ESP_LOGE(TAG, "taskflow import from SD fail:%s!", file);
            }
        } else if( p_json != NULL ) {
            ESP_LOGI(TAG, "taskflow import from json success!");
            used_json = true;
            esp_event_post_to(app_event_loop_handle, CTRL_EVENT_BASE, CTRL_EVENT_TASK_FLOW_START_BY_CMD, 
                                        &p_json,
                                        sizeof(void *), /* ptr size */
                                        portMAX_DELAY); 
        } else {
            ESP_LOGE(TAG, "taskflow import fail!, SD file path or json source must be provided");
        }  
    }

    if( export ) {
        char *p_taskflow = NULL;
        p_taskflow = tf_engine_flow_get();
        if( p_taskflow != NULL ) {
            if( use_sd ) {
                FILE *fp = fopen(file, "w");
                if( fp != NULL ) {
                    fwrite(p_taskflow, strlen(p_taskflow), 1, fp);
                    fclose(fp);
                    ESP_LOGI(TAG, "taskflow export to SD success! %s", file);
                } else {
                    ESP_LOGE(TAG, "taskflow export to SD fail:%s!", file);
                }
            } else {
                ESP_LOGI(TAG, "taskflow:");
                printf("%s\r\n", p_taskflow);
            }
            free(p_taskflow);
        } else {
            ESP_LOGE(TAG, "taskflow is not running, export fail!");
        }
    }

    if( p_json && !used_json ) {
        free(p_json);
    }
    return 0;
}

static void register_cmd_taskflow(void)
{
    taskflow_cfg_args.import =  arg_lit0("i", "import", "import taskflow");
    taskflow_cfg_args.export = arg_lit0("e", "export", "export taskflow");
    taskflow_cfg_args.file =  arg_str0("f", "file", "<string>", "File path, import or export taskflow json string by SD, eg: test.json");
    taskflow_cfg_args.json =  arg_lit0("j", "json", "import taskflow json string by stdin");
    taskflow_cfg_args.end = arg_end(4);

    const esp_console_cmd_t cmd = {
        .command = "taskflow",
        .help = "import taskflow by json string or SD file, eg:taskflow -i -f \"test.json\".\n export taskflow to stdout or SD file, eg: taskflow -e -f \"test.json\"",
        .hint = NULL,
        .func = &taskflow_cmd,
        .argtable = &taskflow_cfg_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/************* factory info get  **************/
static int factory_info_get_cmd(int argc, char **argv)
{
    factory_info_print();
    return 0;
}

static void register_cmd_factory_info(void)
{
    const esp_console_cmd_t cmd = {
        .command = "factory_info",
        .help = "get factory infomation",
        .hint = NULL,
        .func = &factory_info_get_cmd,
        .argtable = NULL
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/************* battery percent get  **************/
static int battery_get_cmd(int argc, char **argv)
{
    uint8_t bat_per = bsp_battery_get_percent();
    printf("battery percentage: %d%%\r\n",bat_per );
    return 0;
}

static void register_cmd_battery(void)
{
    const esp_console_cmd_t cmd = {
        .command = "battery",
        .help = "get battery percent",
        .hint = NULL,
        .func = &battery_get_cmd,
        .argtable = NULL
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/************* bsp function  **************/
static struct {
    struct arg_rex0 *subcmd;
    // struct arg_rex0 *subcmd1;
    // struct arg_rex0 *subcmd2;
    struct arg_end *end;
} bsp_cmd_args;

static int do_bsp_cmd(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
    {
        ESP_LOGD(TAG, "argv[%d]: %s", i, argv[i]);
    }

    if (argc < 2) {
        ESP_LOGW(TAG, "subcmd missing");
        return 1;
    }
    
    char *subcmd = argv[1];
    if (strcmp(subcmd, "i2cdetect") == 0) {
        if (argc < 3) {
            ESP_LOGW(TAG, "i2c bus number missing");
            return 2;
        }
        int bus = atoi(argv[2]);
        if (bus >= I2C_NUM_MAX) {
            ESP_LOGW(TAG, "the system only has %d i2c buses, specified bus %d exceeds range", (int)I2C_NUM_MAX, bus);
            return 3;
        }
        ESP_LOGI(TAG, "i2cdetect on i2c bus %d", bus);
        bsp_i2c_detect((i2c_port_t)bus);
        return 0;
    }
    
    return -1;  // invalid subcmd
}

static void register_bsp_cmd()
{
    // only used to print a neat help
    bsp_cmd_args.subcmd = arg_rex0(NULL, NULL, "i2cdetect <0|1>", NULL, ARG_REX_ICASE, "scan the specified i2c bus");
    bsp_cmd_args.end = arg_end(20);

    const esp_console_cmd_t cmd = {
        .command = "bsp",
        .help = "call bsp functions",
        .hint = "subcmd [subcmd args]",
        .func = do_bsp_cmd,
        .argtable = &bsp_cmd_args
    };

    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/************* record cmd **************/
static struct {
    struct arg_int *time;
    struct arg_str *file;
    struct arg_end *end;
} record_args;

static int record_cmd(int argc, char **argv)
{
    char file[32] = {0};
    char file_wav[32] = {0};
    int record_time = 0;
  
    memset(file, 0, sizeof(file));

    int nerrors = arg_parse(argc, argv, (void **) &record_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, record_args.end, argv[0]);
        return 1;
    }

    if ( record_args.time->count ) {
        record_time = record_args.time->ival[0]; 
    } else {
        record_time = 5;
    }
    ESP_LOGI(TAG, "Record time:%d s", record_time);

    if ( record_args.file->count ) {
        int len = strlen(record_args.file->sval[0]);
        if( len > 0 ){
            snprintf(file, sizeof(file), "/sdcard/%s.pcm", record_args.file->sval[0]);
            snprintf(file_wav, sizeof(file_wav), "/sdcard/%s.wav", record_args.file->sval[0]);
        }
    } else {
        snprintf(file, sizeof(file), "/sdcard/audio_record.pcm");
        snprintf(file_wav, sizeof(file_wav), "/sdcard/audio_record.wav");
    }
    ESP_LOGI(TAG, "save to file:%s", file);

    FILE *fp = fopen(file, "w");
    if( fp == NULL ) {
        ESP_LOGE(TAG, "open file fail:%s!", file);
        return  -1;
    }
    int chunk_len = 1024;
    int write_len = 0;
    int16_t *audio_buffer = heap_caps_malloc( chunk_len, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT); //TODO 

    time_t now = 0;
    time_t start = 0;
    int total_len = 0;

    bsp_codec_set_fs(16000, 16, 1);
    time(&start); 
    do {
        bsp_get_feed_data(false, audio_buffer, chunk_len);
        fwrite(audio_buffer, 1, chunk_len, fp);
        total_len+=chunk_len;
        ESP_LOGI(TAG, "fwrite:%d", chunk_len);
        time(&now); 
    } while ( difftime(now, start) <= record_time );
    fclose(fp);
    bsp_codec_dev_stop();
    ESP_LOGI(TAG, "record end ,size%d", total_len);


    vTaskDelay(pdMS_TO_TICKS(1000));
    
    //save wav file
    audio_wav_header_t wav_head = {};
    memcpy(&wav_head.ChunkID, "RIFF", 4);
    wav_head.ChunkSize = sizeof(audio_wav_header_t) + total_len - 8;
    memcpy(&wav_head.Format, "WAVE", 4);

    memcpy(&wav_head.Subchunk1ID, "fmt ", 4);
    wav_head.Subchunk1Size = 16;
    wav_head.AudioFormat = 1;
    wav_head.NumChannels = 1;
    wav_head.SampleRate = 16000;
    wav_head.ByteRate = wav_head.SampleRate * wav_head.BitsPerSample * wav_head.NumChannels / 8;
    wav_head.BitsPerSample = 16;
    wav_head.BlockAlign = wav_head.BitsPerSample * wav_head.NumChannels / 8;
    
    memcpy(&wav_head.Subchunk2ID, "data", 4);
    wav_head.Subchunk2Size = total_len;
   
    FILE *fp_wav = fopen(file_wav, "w");
    if( fp_wav == NULL ) {
        ESP_LOGE(TAG, "open file fail:%s!", file_wav);
        free(audio_buffer);
        return  -1;
    }
    fp = fopen(file, "r");
    if( fp == NULL ) {
        ESP_LOGE(TAG, "open file fail:%s!", file);
        free(audio_buffer);
        return  -1;
    }
    fseek(fp, 0, SEEK_SET);

    int read_len = 0;

    if (fwrite((void *)&wav_head, 1, sizeof(audio_wav_header_t), fp_wav) != sizeof(audio_wav_header_t)) {
        ESP_LOGW(TAG, "Error in writing to file");
    }

    while ( total_len > 0) {
        read_len = fread(audio_buffer, 1, chunk_len,  fp);
        if (read_len <= 0) {
            break;
        }
        fwrite(audio_buffer, 1, chunk_len, fp_wav);
        total_len -= read_len;
        ESP_LOGI(TAG, "fwrite:%d", read_len);
    }
    fclose(fp_wav);
    fclose(fp);
    free(audio_buffer);
    ESP_LOGI(TAG, "save wav end");

    return 0;
}

static void register_cmd_record(void)
{
    record_args.time =  arg_int0("t", "time", "<int>", "record time, s");
    record_args.file =  arg_str0("f", "file", "<string>", "File path, Store PCM audio data in SD card");
    record_args.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "record",
        .help = "record audio and save to SD.",
        .hint = NULL,
        .func = &record_cmd,
        .argtable = &record_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/************* voice interaction cmd **************/
static struct {
    struct arg_lit *vi_start;
    struct arg_lit *vi_end;
    struct arg_lit *vi_stop;
    struct arg_int *vi_exit;
    struct arg_end *end;
} vi_ctrl_args;

static int vi_ctrl_cmd(int argc, char **argv)
{
    char file[32] = {0};
    char file_wav[32] = {0};
    int record_time = 0;
  
    memset(file, 0, sizeof(file));

    int nerrors = arg_parse(argc, argv, (void **) &vi_ctrl_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, vi_ctrl_args.end, argv[0]);
        return 1;
    }
    
    if (vi_ctrl_args.vi_start->count) {
        printf("start record\n");
        esp_event_post_to(app_event_loop_handle, CTRL_EVENT_BASE, \
                    CTRL_EVENT_VI_RECORD_WAKEUP, NULL, NULL, pdMS_TO_TICKS(10000));
    } else if( vi_ctrl_args.vi_end->count ){
        printf("end record\n");
        esp_event_post_to(app_event_loop_handle, CTRL_EVENT_BASE, \
                    CTRL_EVENT_VI_RECORD_STOP, NULL, NULL, pdMS_TO_TICKS(10000));
    } else if( vi_ctrl_args.vi_stop->count ){
        printf("stop voice interaction\n");
        esp_event_post_to(app_event_loop_handle, VIEW_EVENT_BASE, \
                    VIEW_EVENT_VI_STOP, NULL, NULL, pdMS_TO_TICKS(10000));
    } else if( vi_ctrl_args.vi_exit->count ){
        printf("exit voice interaction\n");
        
        int exit_mode = vi_ctrl_args.vi_exit->ival[0]; 

        esp_event_post_to(app_event_loop_handle, VIEW_EVENT_BASE, \
                    VIEW_EVENT_VI_EXIT, &exit_mode, sizeof(exit_mode), pdMS_TO_TICKS(10000));
    }

    return 0;
}

static void register_cmd_vi_ctrl(void)
{
    vi_ctrl_args.vi_start =  arg_lit0("s", "start", "start wakeup, and start record");
    vi_ctrl_args.vi_end = arg_lit0("e", "end", "end record");
    vi_ctrl_args.vi_stop = arg_lit0("c", "stop", "stop voice interaction when analyzing or palying, Put it into idle.");
    vi_ctrl_args.vi_exit = arg_int0("z", "exit", "<int>", "0: exit vi, 1:exit vi then run new taskflow");
    vi_ctrl_args.end = arg_end(4);

    const esp_console_cmd_t cmd = {
        .command = "vi_ctrl",
        .help = "voice interaction ctrl.",
        .hint = NULL,
        .func = &vi_ctrl_cmd,
        .argtable = &vi_ctrl_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/************* rgb cmd **************/
static struct {
    struct arg_int *r;
    struct arg_int *g;
    struct arg_int *b;
    struct arg_int *mode;
    struct arg_int *step_value;
    struct arg_int *step_time_ms;
    struct arg_end *end;
} rgb_args;

static int rgb_cmd(int argc, char **argv)
{
    int r, g, b, mode, step_value, step_time_ms;
    int nerrors = arg_parse(argc, argv, (void **) &rgb_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, rgb_args.end, argv[0]);
        return 1;
    }

    if ( rgb_args.r->count ) {
        r = rgb_args.r->ival[0]; 
    } else {
        r = 0;
    }

    if ( rgb_args.g->count ) {
        g = rgb_args.g->ival[0];
    } else {
        g = 0;
    }

    if ( rgb_args.b->count ) {
        b = rgb_args.b->ival[0];
    } else {
        b = 0;
    }

    if ( rgb_args.mode->count ) {
        mode = rgb_args.mode->ival[0];
    } else {
        mode = 3;
    }

    if ( rgb_args.step_value->count ) {
        step_value = rgb_args.step_value->ival[0];
    } else {
        step_value = 3;
    }

    if ( rgb_args.step_time_ms->count ) {
        step_time_ms = rgb_args.step_time_ms->ival[0];
    } else {
        step_time_ms = 5;
    }

    app_rgb_status_set(r, g, b, mode, step_value, step_time_ms);
    return 0;
}

static void register_cmd_rgb(void)
{
    rgb_args.r =  arg_int0("r", "red", "<int>", "red value, 0~255");
    rgb_args.g =  arg_int0("g", "green", "<int>", "green value, 0~255");
    rgb_args.b =  arg_int0("b", "blue", "<int>", "blue value, 0~255");
    rgb_args.mode =  arg_int0("m", "mode", "<int>", "1: breath, 2: blink, 3:solid, default 3");
    rgb_args.step_value =  arg_int0("v", "step_value", "<int>", "RGB step value, default 3");
    rgb_args.step_time_ms =  arg_int0("t", "step_time_ms", "<int>", "RGB step time(ms), default 5");
    rgb_args.end = arg_end(6);

    const esp_console_cmd_t cmd = {
        .command = "rgb",
        .help = "set rgb value. eg: rgb -r 255 -g 0 -b 0 -m 3",
        .hint = NULL,
        .func = &rgb_cmd,
        .argtable = &rgb_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}



/************* cmd register **************/

// Single console/REPL owner, split into a prepare phase (command registration + REPL/driver creation, no
// blocking read) and a start phase (esp_console_start_repl -- the call that actually wakes the REPL task and
// begins linenoise/history). This split exists so a caller (main.c, gated by CONFIG_GPTNIX_WATCHER_PROVISION)
// can safely read raw bytes off the already-installed console UART BETWEEN prepare and start, during the
// window before esp_console_start_repl() has woken the REPL task -- see
// app_gptnix_watcher_provision.c for the consumer of that window. Neither function knows anything about the
// M3A provisioning protocol/token; this file owns only the console/REPL lifecycle.
static esp_console_repl_t *s_repl = NULL;
static bool s_repl_prepared = false;
static bool s_repl_started = false;

int app_cmd_prepare_repl(void)
{
    if (s_repl_prepared) {
        ESP_LOGE(TAG, "app_cmd_prepare_repl: already prepared -- refusing to re-register commands or install a second driver");
        return -1;
    }

#if CONFIG_ENABLE_FACTORY_FW_DEBUG_LOG
    esp_log_level_set(TAG, ESP_LOG_DEBUG);
#endif

    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    /* Prompt to be printed before each line.
     * This can be customized, made dynamic, etc.
     */
    repl_config.prompt = PROMPT_STR ">";
    repl_config.max_cmdline_length = 1024;

    register_cmd_wifi_sta();
    register_cmd_force_ota();
    register_cmd_taskflow();
    register_cmd_factory_info();
    register_cmd_battery();
    register_bsp_cmd();
    register_cmd_reboot();
    register_cmd_factory_reset();
    register_cmd_record();
    register_cmd_vi_ctrl();
    register_cmd_iperf();
    register_cmd_rgb();

#if defined(CONFIG_ESP_CONSOLE_UART_DEFAULT) || defined(CONFIG_ESP_CONSOLE_UART_CUSTOM)
    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&hw_config, &repl_config, &s_repl));

#elif defined(CONFIG_ESP_CONSOLE_USB_CDC)
    esp_console_dev_usb_cdc_config_t hw_config = ESP_CONSOLE_DEV_CDC_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_cdc(&hw_config, &repl_config, &s_repl));

#elif defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG)
    esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&hw_config, &repl_config, &s_repl));

#else
#error Unsupported console type
#endif

    s_repl_prepared = true;
    return 0;
}

int app_cmd_start_repl(void)
{
    if (!s_repl_prepared) {
        ESP_LOGE(TAG, "app_cmd_start_repl: REPL not prepared -- call app_cmd_prepare_repl() first");
        return -1;
    }
    if (s_repl_started) {
        ESP_LOGE(TAG, "app_cmd_start_repl: REPL already started -- refusing a second start");
        return -1;
    }
    // Since we have SD card access in console cmd, it might trigger the SPI core-conflict issue
    // we can't control the core on which the console runs, so
    // TODO: narrow the SD card access code into another task which runs on Core 1.
    ESP_ERROR_CHECK(esp_console_start_repl(s_repl));
    s_repl_started = true;
    return 0;
}

// Compatibility wrapper for the normal (CONFIG_GPTNIX_WATCHER_PROVISION unset) boot path: unchanged external
// behavior -- prepare immediately followed by start, exactly as the original single-phase app_cmd_init() did.
int app_cmd_init(void)
{
    int ret = app_cmd_prepare_repl();
    if (ret != 0) {
        return ret;
    }
    return app_cmd_start_repl();
}
