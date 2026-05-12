// The DocBoy reporter uses direct HRAM access to detect test results.

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include <Core/gb.h>

#define DOCBOY_RESULT_ADDRESS 0xFFF0
#define DOCBOY_RESULT_HRAM_OFFSET (DOCBOY_RESULT_ADDRESS - 0xFF80)
#define CYCLES_PER_FRAME 139810

typedef enum {
    TEST_PASS,
    TEST_FAIL,
    TEST_UNKNOWN,
    TEST_ERROR,
} test_status_t;

typedef struct {
    char *path;
    char *display_path;
    GB_model_t model;
    const char *boot_rom_name;
    bool has_result_marker;
} rom_entry_t;

typedef struct {
    rom_entry_t *entries;
    size_t count;
    size_t capacity;
} rom_list_t;

typedef struct {
    const char *docboy_root;
    const char *bootrom_dir;
    const char *markdown_path;
    unsigned timeout_frames;
} options_t;

static uint32_t bitmap[256 * 224];

static void usage(const char *argv0)
{
    fprintf(stderr,
            "SameBoy DocBoy Reporter v" GB_VERSION "\n"
            "Usage: %s --docboy-root path [--timeout-frames frames] [--bootrom-dir path] [--markdown path]\n",
            argv0);
}

static void *xmalloc(size_t size)
{
    void *ret = malloc(size);
    if (!ret) {
        perror("malloc");
        exit(1);
    }
    return ret;
}

static char *xstrdup(const char *string)
{
    char *ret = strdup(string);
    if (!ret) {
        perror("strdup");
        exit(1);
    }
    return ret;
}

static char *path_join(const char *a, const char *b)
{
    size_t a_length = strlen(a);
    size_t b_length = strlen(b);
    bool add_separator = a_length && a[a_length - 1] != '/' && a[a_length - 1] != '\\';
    char *ret = xmalloc(a_length + add_separator + b_length + 1);
    memcpy(ret, a, a_length);
    if (add_separator) {
        ret[a_length++] = '/';
    }
    memcpy(ret + a_length, b, b_length);
    ret[a_length + b_length] = 0;
    return ret;
}

static char *path_join_replacing_extension(const char *directory, const char *relative_path, const char *extension)
{
    size_t relative_length = strlen(relative_path);
    size_t stem_length = relative_length;
    for (size_t i = relative_length; i--;) {
        if (relative_path[i] == '/' || relative_path[i] == '\\') {
            break;
        }
        if (relative_path[i] == '.') {
            stem_length = i;
            break;
        }
    }

    size_t directory_length = strlen(directory);
    size_t extension_length = strlen(extension);
    bool add_separator = directory_length && directory[directory_length - 1] != '/' && directory[directory_length - 1] != '\\';
    char *ret = xmalloc(directory_length + add_separator + stem_length + extension_length + 1);
    memcpy(ret, directory, directory_length);
    if (add_separator) {
        ret[directory_length++] = '/';
    }
    memcpy(ret + directory_length, relative_path, stem_length);
    memcpy(ret + directory_length + stem_length, extension, extension_length);
    ret[directory_length + stem_length + extension_length] = 0;
    return ret;
}

static bool has_suffix(const char *string, const char *suffix)
{
    size_t string_length = strlen(string);
    size_t suffix_length = strlen(suffix);
    if (string_length < suffix_length) {
        return false;
    }
    return strcmp(string + string_length - suffix_length, suffix) == 0;
}

static bool is_rom_path(const char *path)
{
    return has_suffix(path, ".gb") || has_suffix(path, ".gbc");
}

static int compare_rom_entries(const void *a, const void *b)
{
    const rom_entry_t *entry_a = a;
    const rom_entry_t *entry_b = b;
    int display_compare = strcmp(entry_a->display_path, entry_b->display_path);
    if (display_compare) {
        return display_compare;
    }
    return strcmp(entry_a->path, entry_b->path);
}

static void append_rom(rom_list_t *list, const char *path, const char *display_path, GB_model_t model, const char *boot_rom_name,
                       bool has_result_marker)
{
    if (list->count == list->capacity) {
        list->capacity = list->capacity? list->capacity * 2 : 256;
        rom_entry_t *entries = realloc(list->entries, sizeof(*entries) * list->capacity);
        if (!entries) {
            perror("realloc");
            exit(1);
        }
        list->entries = entries;
    }

    list->entries[list->count++] = (rom_entry_t) {
        .path = xstrdup(path),
        .display_path = xstrdup(display_path),
        .model = model,
        .boot_rom_name = boot_rom_name,
        .has_result_marker = has_result_marker,
    };
}

static bool source_has_result_marker(const char *path)
{
    FILE *file = fopen(path, "r");
    if (!file) {
        return true;
    }

    bool ret = false;
    char line[4096];
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "TestSuccess") || strstr(line, "TestFail")) {
            ret = true;
            break;
        }
    }
    fclose(file);
    return ret;
}

static void free_rom_list(rom_list_t *list)
{
    for (size_t i = 0; i < list->count; i++) {
        free(list->entries[i].path);
        free(list->entries[i].display_path);
    }
    free(list->entries);
}

#ifdef _WIN32
static bool is_directory_attributes(unsigned attributes)
{
    return attributes & _A_SUBDIR;
}

static int collect_roms_in_directory(rom_list_t *list, const char *directory, const char *display_root,
                                     const char *variant_root, const char *source_root,
                                     GB_model_t model, const char *boot_rom_name)
{
    char *pattern = path_join(directory, "*");
    struct _finddata_t data;
    intptr_t handle = _findfirst(pattern, &data);
    free(pattern);

    if (handle == -1) {
        return errno == ENOENT ? 0 : -1;
    }

    do {
        if (strcmp(data.name, ".") == 0 || strcmp(data.name, "..") == 0) {
            continue;
        }

        char *path = path_join(directory, data.name);
        if (is_directory_attributes(data.attrib)) {
            if (collect_roms_in_directory(list, path, display_root, variant_root, source_root, model, boot_rom_name)) {
                free(path);
                _findclose(handle);
                return -1;
            }
        }
        else if (is_rom_path(path)) {
            const char *display_path = path + strlen(display_root);
            if (*display_path == '/' || *display_path == '\\') {
                display_path++;
            }
            const char *variant_relative_path = path + strlen(variant_root);
            if (*variant_relative_path == '/' || *variant_relative_path == '\\') {
                variant_relative_path++;
            }
            char *source_path = path_join_replacing_extension(source_root, variant_relative_path, ".asm");
            append_rom(list, path, display_path, model, boot_rom_name, source_has_result_marker(source_path));
            free(source_path);
        }
        free(path);
    } while (_findnext(handle, &data) == 0);

    _findclose(handle);
    return 0;
}
#else
static int collect_roms_in_directory(rom_list_t *list, const char *directory, const char *display_root,
                                     const char *variant_root, const char *source_root,
                                     GB_model_t model, const char *boot_rom_name)
{
    DIR *dir = opendir(directory);
    if (!dir) {
        return errno == ENOENT ? 0 : -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char *path = path_join(directory, entry->d_name);
        struct stat stat_buffer;
        if (stat(path, &stat_buffer)) {
            free(path);
            closedir(dir);
            return -1;
        }

        if (S_ISDIR(stat_buffer.st_mode)) {
            if (collect_roms_in_directory(list, path, display_root, variant_root, source_root, model, boot_rom_name)) {
                free(path);
                closedir(dir);
                return -1;
            }
        }
        else if (S_ISREG(stat_buffer.st_mode) && is_rom_path(path)) {
            const char *display_path = path + strlen(display_root);
            if (*display_path == '/') {
                display_path++;
            }
            const char *variant_relative_path = path + strlen(variant_root);
            if (*variant_relative_path == '/') {
                variant_relative_path++;
            }
            char *source_path = path_join_replacing_extension(source_root, variant_relative_path, ".asm");
            append_rom(list, path, display_path, model, boot_rom_name, source_has_result_marker(source_path));
            free(source_path);
        }
        free(path);
    }

    closedir(dir);
    return 0;
}
#endif

static int collect_docboy_roms(rom_list_t *list, const char *docboy_root)
{
    struct {
        const char *name;
        GB_model_t model;
        const char *boot_rom_name;
    } variants[] = {
        {"dmg", GB_MODEL_DMG_B, "dmg_boot.bin"},
        {"cgb", GB_MODEL_CGB_E, "cgb_boot.bin"},
        {"cgb_dmg_mode", GB_MODEL_CGB_E, "cgb_boot.bin"},
        {"cgb_dmg_ext_mode", GB_MODEL_CGB_E, "cgb_boot.bin"},
    };

    char *roms_root = path_join(docboy_root, "roms");
    char *source_root = path_join(docboy_root, "source");
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        char *variant_root = path_join(roms_root, variants[i].name);
        char *variant_source_root = path_join(source_root, variants[i].name);
        if (collect_roms_in_directory(list, variant_root, roms_root, variant_root, variant_source_root,
                                      variants[i].model, variants[i].boot_rom_name)) {
            fprintf(stderr, "Failed to scan '%s': %s\n", variant_root, strerror(errno));
            free(variant_source_root);
            free(variant_root);
            free(source_root);
            free(roms_root);
            return -1;
        }
        free(variant_source_root);
        free(variant_root);
    }
    free(source_root);
    free(roms_root);

    qsort(list->entries, list->count, sizeof(*list->entries), compare_rom_entries);
    return 0;
}

static char *executable_folder(void)
{
    static char path[1024] = {0,};
    if (path[0]) {
        return path;
    }

#ifdef __APPLE__
    uint32_t length = sizeof(path) - 1;
    if (_NSGetExecutablePath(path, &length)) {
        getcwd(path, sizeof(path) - 1);
        return path;
    }
#else
#ifdef __linux__
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length == -1) {
        getcwd(path, sizeof(path) - 1);
        return path;
    }
    path[length] = 0;
#else
#ifdef _WIN32
    HMODULE hModule = GetModuleHandle(NULL);
    GetModuleFileName(hModule, path, sizeof(path) - 1);
#else
    getcwd(path, sizeof(path) - 1);
    return path;
#endif
#endif
#endif

    size_t pos = strlen(path);
    while (pos) {
        pos--;
        if (path[pos] == '/' || path[pos] == '\\') {
            path[pos] = 0;
            break;
        }
    }
    return path;
}

static uint32_t rgb_encode(GB_gameboy_t *gb, uint8_t r, uint8_t g, uint8_t b)
{
    (void) gb;
#ifdef GB_BIG_ENDIAN
    return (uint32_t) r << 0 | (uint32_t) g << 8 | (uint32_t) b << 16;
#else
    return (uint32_t) r << 24 | (uint32_t) g << 16 | (uint32_t) b << 8;
#endif
}

static void log_callback(GB_gameboy_t *gb, const char *string, GB_log_attributes_t attributes)
{
    (void) gb;
    (void) string;
    (void) attributes;
}

static test_status_t run_rom(const rom_entry_t *rom, const options_t *options)
{
    if (!rom->has_result_marker) {
        return TEST_UNKNOWN;
    }

    GB_gameboy_t *gb = GB_init(GB_alloc(), rom->model);
    if (!gb) {
        return TEST_ERROR;
    }

    char *boot_rom_path = path_join(options->bootrom_dir, rom->boot_rom_name);
    if (GB_load_boot_rom(gb, boot_rom_path)) {
        fprintf(stderr, "Failed to load boot ROM from '%s'\n", boot_rom_path);
        free(boot_rom_path);
        GB_free(gb);
        GB_dealloc(gb);
        return TEST_ERROR;
    }
    free(boot_rom_path);

    GB_set_pixels_output(gb, bitmap);
    GB_set_rgb_encode_callback(gb, rgb_encode);
    GB_set_log_callback(gb, log_callback);
    GB_set_color_correction_mode(gb, GB_COLOR_CORRECTION_EMULATE_HARDWARE);
    GB_set_rtc_mode(gb, GB_RTC_MODE_ACCURATE);
    GB_set_emulate_joypad_bouncing(gb, false);
    GB_set_turbo_mode(gb, true, true);
    GB_set_turbo_cap(gb, 0);

    if (GB_load_rom(gb, rom->path)) {
        fprintf(stderr, "Failed to load ROM '%s': %s\n", rom->path, strerror(errno));
        GB_free(gb);
        GB_dealloc(gb);
        return TEST_ERROR;
    }

    size_t hram_size = 0;
    uint8_t *hram = GB_get_direct_access(gb, GB_DIRECT_ACCESS_HRAM, &hram_size, NULL);
    if (!hram || hram_size <= DOCBOY_RESULT_HRAM_OFFSET) {
        GB_free(gb);
        GB_dealloc(gb);
        return TEST_ERROR;
    }

    hram[DOCBOY_RESULT_HRAM_OFFSET] = 0;

    test_status_t result = TEST_UNKNOWN;
    unsigned frames = 0;
    unsigned cycles = 0;
    while (frames < options->timeout_frames) {
        uint8_t marker = hram[DOCBOY_RESULT_HRAM_OFFSET];
        if (marker == 1) {
            result = TEST_PASS;
            break;
        }
        if (marker == 2) {
            result = TEST_FAIL;
            break;
        }

        cycles += GB_run(gb);
        while (cycles >= CYCLES_PER_FRAME) {
            frames++;
            cycles -= CYCLES_PER_FRAME;
        }
    }

    GB_free(gb);
    GB_dealloc(gb);
    return result;
}

static const char *status_string(test_status_t status)
{
    switch (status) {
        case TEST_PASS: return "✅";
        case TEST_FAIL: return "❌";
        case TEST_UNKNOWN: return "?";
        case TEST_ERROR: return "⚠️";
    }
    return "?";
}

static const char *markdown_status_string(test_status_t status)
{
    if (status == TEST_UNKNOWN) {
        return "❌";
    }
    return status_string(status);
}

static void print_markdown_cell(FILE *file, const char *string)
{
    for (const char *p = string; *p; p++) {
        if (*p == '|' || *p == '\\') {
            fputc('\\', file);
        }
        fputc(*p, file);
    }
}

static int write_report(const char *path, const rom_list_t *list, const test_status_t *statuses)
{
    FILE *file = stdout;
    if (path && strcmp(path, "-") != 0) {
        file = fopen(path, "w");
        if (!file) {
            fprintf(stderr, "Failed to open '%s': %s\n", path, strerror(errno));
            return -1;
        }
    }

    size_t passed = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (statuses[i] == TEST_PASS) {
            passed++;
        }
    }

    fprintf(file, "# Test Report (%zu/%zu)\n\n", passed, list->count);
    fprintf(file, "| family | rom | status |\n");
    fprintf(file, "| --- | --- | --- |\n");
    for (size_t i = 0; i < list->count; i++) {
        fprintf(file, "| docboy | ");
        print_markdown_cell(file, list->entries[i].display_path);
        fprintf(file, " | %s |\n", markdown_status_string(statuses[i]));
    }

    if (file != stdout) {
        fclose(file);
    }
    return 0;
}

static bool parse_unsigned(const char *string, unsigned *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(string, &end, 10);
    if (errno || !end || *end || value > UINT_MAX) {
        return false;
    }
    *out = (unsigned) value;
    return true;
}

int main(int argc, char **argv)
{
    options_t options = {
        .timeout_frames = 3600,
        .bootrom_dir = executable_folder(),
    };

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--docboy-root") == 0 && i != argc - 1) {
            options.docboy_root = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--timeout-frames") == 0 && i != argc - 1) {
            if (!parse_unsigned(argv[++i], &options.timeout_frames) || options.timeout_frames == 0) {
                fprintf(stderr, "Invalid timeout frame count\n");
                return 1;
            }
            continue;
        }
        if (strcmp(argv[i], "--bootrom-dir") == 0 && i != argc - 1) {
            options.bootrom_dir = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--markdown") == 0 && i != argc - 1) {
            options.markdown_path = argv[++i];
            continue;
        }

        usage(argv[0]);
        return 1;
    }

    if (!options.docboy_root) {
        usage(argv[0]);
        return 1;
    }

    GB_random_set_enabled(false);

    rom_list_t list = {0};
    if (collect_docboy_roms(&list, options.docboy_root)) {
        free_rom_list(&list);
        return 1;
    }

    if (!list.count) {
        fprintf(stderr, "No DocBoy ROMs found under '%s/roms'\n", options.docboy_root);
        free_rom_list(&list);
        return 1;
    }

    test_status_t *statuses = xmalloc(sizeof(*statuses) * list.count);
    for (size_t i = 0; i < list.count; i++) {
        statuses[i] = run_rom(&list.entries[i], &options);
        fprintf(stderr, "[%zu/%zu] %s %s\n", i + 1, list.count, status_string(statuses[i]), list.entries[i].display_path);
    }

    int ret = write_report(options.markdown_path, &list, statuses);
    free(statuses);
    free_rom_list(&list);
    return ret ? 1 : 0;
}
