// The DocBoy reporter uses low-level state to detect test results and visual test completion.
#define GB_INTERNAL

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

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
    char *reference_png_path;
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

typedef struct {
    unsigned width;
    unsigned height;
    uint8_t *rgb;
} png_image_t;

static uint32_t bitmap[256 * 224];
static const GB_palette_t docboy_dmg_palette = {{{0x10, 0x40, 0x00},
                                                 {0x29, 0x55, 0x00},
                                                 {0x4A, 0x69, 0x00},
                                                 {0x83, 0x95, 0x00},
                                                 {0x83, 0x95, 0x00}}};

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

static void remove_path_component(char *path, const char *component, char separator)
{
    size_t component_length = strlen(component);
    size_t pattern_length = component_length + 1;
    char pattern[64];

    if (pattern_length >= sizeof(pattern)) {
        return;
    }

    pattern[0] = separator;
    memcpy(pattern + 1, component, component_length);
    pattern[pattern_length] = 0;

    char *component_start = strstr(path, pattern);
    if (component_start) {
        memmove(component_start, component_start + pattern_length, strlen(component_start + pattern_length) + 1);
    }
}

static void remove_reference_visual_component(char *path)
{
    remove_path_component(path, "interactive_visual", '/');
    remove_path_component(path, "visual", '/');
    remove_path_component(path, "interactive_visual", '\\');
    remove_path_component(path, "visual", '\\');
}

static bool path_exists(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        return false;
    }
    fclose(file);
    return true;
}

static char *reference_png_path_for_rom(const char *results_root, const char *variant_relative_path)
{
    char *ret = path_join_replacing_extension(results_root, variant_relative_path, ".png");
    remove_reference_visual_component(ret);
    if (!path_exists(ret)) {
        free(ret);
        return NULL;
    }
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

static void append_rom(rom_list_t *list, const char *path, const char *display_path, const char *reference_png_path,
                       GB_model_t model, const char *boot_rom_name, bool has_result_marker)
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
        .reference_png_path = reference_png_path ? xstrdup(reference_png_path) : NULL,
        .model = model,
        .boot_rom_name = boot_rom_name,
        .has_result_marker = has_result_marker,
    };
}

static bool source_has_result_marker(const char *path, bool *found)
{
    FILE *file = fopen(path, "r");
    if (!file) {
        *found = false;
        return false;
    }

    *found = true;
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
        free(list->entries[i].reference_png_path);
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
                                     const char *results_root,
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
            if (collect_roms_in_directory(list, path, display_root, variant_root, source_root, results_root,
                                          model, boot_rom_name)) {
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
            char *reference_png_path = reference_png_path_for_rom(results_root, variant_relative_path);
            bool source_found = false;
            bool has_result_marker = source_has_result_marker(source_path, &source_found);
            if (!source_found) {
                has_result_marker = reference_png_path == NULL;
            }
            append_rom(list, path, display_path, reference_png_path, model, boot_rom_name, has_result_marker);
            free(reference_png_path);
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
                                     const char *results_root,
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
            if (collect_roms_in_directory(list, path, display_root, variant_root, source_root, results_root,
                                          model, boot_rom_name)) {
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
            char *reference_png_path = reference_png_path_for_rom(results_root, variant_relative_path);
            bool source_found = false;
            bool has_result_marker = source_has_result_marker(source_path, &source_found);
            if (!source_found) {
                has_result_marker = reference_png_path == NULL;
            }
            append_rom(list, path, display_path, reference_png_path, model, boot_rom_name, has_result_marker);
            free(reference_png_path);
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
    char *results_root = path_join(docboy_root, "results");
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        char *variant_root = path_join(roms_root, variants[i].name);
        char *variant_source_root = path_join(source_root, variants[i].name);
        if (collect_roms_in_directory(list, variant_root, roms_root, variant_root, variant_source_root, results_root,
                                      variants[i].model, variants[i].boot_rom_name)) {
            fprintf(stderr, "Failed to scan '%s': %s\n", variant_root, strerror(errno));
            free(variant_source_root);
            free(variant_root);
            free(results_root);
            free(source_root);
            free(roms_root);
            return -1;
        }
        free(variant_source_root);
        free(variant_root);
    }
    free(results_root);
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

static uint32_t read_be32(const uint8_t *data)
{
    return ((uint32_t) data[0] << 24) |
           ((uint32_t) data[1] << 16) |
           ((uint32_t) data[2] << 8) |
           (uint32_t) data[3];
}

static bool append_buffer(uint8_t **buffer, size_t *size, const uint8_t *data, size_t data_size)
{
    uint8_t *new_buffer = realloc(*buffer, *size + data_size);
    if (!new_buffer) {
        return false;
    }
    memcpy(new_buffer + *size, data, data_size);
    *buffer = new_buffer;
    *size += data_size;
    return true;
}

static bool read_file(const char *path, uint8_t **data, size_t *size)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        return false;
    }

    if (fseek(file, 0, SEEK_END)) {
        fclose(file);
        return false;
    }

    long length = ftell(file);
    if (length < 0) {
        fclose(file);
        return false;
    }

    rewind(file);
    *data = xmalloc((size_t) length);
    *size = (size_t) length;
    if (fread(*data, 1, *size, file) != *size) {
        free(*data);
        *data = NULL;
        *size = 0;
        fclose(file);
        return false;
    }

    fclose(file);
    return true;
}

static uint8_t paeth_predictor(uint8_t a, uint8_t b, uint8_t c)
{
    int p = (int) a + (int) b - (int) c;
    int pa = abs(p - (int) a);
    int pb = abs(p - (int) b);
    int pc = abs(p - (int) c);

    if (pa <= pb && pa <= pc) {
        return a;
    }
    if (pb <= pc) {
        return b;
    }
    return c;
}

static bool decode_png_rgb(const uint8_t *png, size_t png_size, png_image_t *image)
{
    static const uint8_t png_signature[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    if (png_size < sizeof(png_signature) || memcmp(png, png_signature, sizeof(png_signature))) {
        return false;
    }

    uint32_t width = 0;
    uint32_t height = 0;
    uint8_t bit_depth = 0;
    uint8_t color_type = 0;
    uint8_t *idat = NULL;
    size_t idat_size = 0;

    size_t offset = sizeof(png_signature);
    while (offset + 12 <= png_size) {
        uint32_t chunk_size = read_be32(png + offset);
        offset += 4;
        const uint8_t *chunk_type = png + offset;
        offset += 4;

        if (chunk_size > png_size - offset - 4) {
            free(idat);
            return false;
        }

        const uint8_t *chunk_data = png + offset;
        offset += chunk_size + 4; /* Skip data and CRC */

        if (!memcmp(chunk_type, "IHDR", 4)) {
            if (chunk_size != 13) {
                free(idat);
                return false;
            }
            width = read_be32(chunk_data);
            height = read_be32(chunk_data + 4);
            bit_depth = chunk_data[8];
            color_type = chunk_data[9];
            if (chunk_data[10] != 0 || chunk_data[11] != 0 || chunk_data[12] != 0) {
                free(idat);
                return false;
            }
        }
        else if (!memcmp(chunk_type, "IDAT", 4)) {
            if (!append_buffer(&idat, &idat_size, chunk_data, chunk_size)) {
                free(idat);
                return false;
            }
        }
        else if (!memcmp(chunk_type, "IEND", 4)) {
            break;
        }
    }

    if (!width || !height || bit_depth != 8 || color_type != 2 || !idat_size) {
        free(idat);
        return false;
    }

    if ((size_t) width > SIZE_MAX / 3 || (size_t) height > SIZE_MAX / (1 + (size_t) width * 3)) {
        free(idat);
        return false;
    }

    size_t stride = (size_t) width * 3;
    size_t filtered_size = (stride + 1) * height;
    uint8_t *filtered = xmalloc(filtered_size);
    uLongf actual_filtered_size = filtered_size;
    int zret = uncompress(filtered, &actual_filtered_size, idat, idat_size);
    free(idat);
    if (zret != Z_OK || actual_filtered_size != filtered_size) {
        free(filtered);
        return false;
    }

    uint8_t *rgb = xmalloc(stride * height);
    for (uint32_t y = 0; y < height; y++) {
        const uint8_t *src = filtered + y * (stride + 1);
        uint8_t filter = src[0];
        src++;
        uint8_t *dest = rgb + y * stride;
        const uint8_t *previous = y ? dest - stride : NULL;

        if (filter > 4) {
            free(filtered);
            free(rgb);
            return false;
        }

        for (size_t x = 0; x < stride; x++) {
            uint8_t left = x >= 3 ? dest[x - 3] : 0;
            uint8_t up = previous ? previous[x] : 0;
            uint8_t up_left = previous && x >= 3 ? previous[x - 3] : 0;

            switch (filter) {
                case 0: dest[x] = src[x]; break;
                case 1: dest[x] = src[x] + left; break;
                case 2: dest[x] = src[x] + up; break;
                case 3: dest[x] = src[x] + ((uint16_t) left + up) / 2; break;
                case 4: dest[x] = src[x] + paeth_predictor(left, up, up_left); break;
            }
        }
    }

    free(filtered);
    image->width = width;
    image->height = height;
    image->rgb = rgb;
    return true;
}

static bool load_png_rgb(const char *path, png_image_t *image)
{
    uint8_t *png = NULL;
    size_t png_size = 0;
    if (!read_file(path, &png, &png_size)) {
        return false;
    }

    bool ret = decode_png_rgb(png, png_size, image);
    free(png);
    return ret;
}

static void free_png_image(png_image_t *image)
{
    free(image->rgb);
    image->rgb = NULL;
}

static void bitmap_pixel_rgb(uint32_t pixel, uint8_t *r, uint8_t *g, uint8_t *b)
{
#ifdef GB_BIG_ENDIAN
    *r = pixel >> 0;
    *g = pixel >> 8;
    *b = pixel >> 16;
#else
    *r = pixel >> 24;
    *g = pixel >> 16;
    *b = pixel >> 8;
#endif
}

static test_status_t compare_reference_png(GB_gameboy_t *gb, const char *reference_png_path)
{
    png_image_t expected = {0};
    if (!load_png_rgb(reference_png_path, &expected)) {
        fprintf(stderr, "Failed to load reference PNG '%s'\n", reference_png_path);
        return TEST_ERROR;
    }

    unsigned width = GB_get_screen_width(gb);
    unsigned height = GB_get_screen_height(gb);
    if (expected.width != width || expected.height != height) {
        fprintf(stderr, "Reference PNG '%s' has size %ux%u, expected %ux%u\n",
                reference_png_path, expected.width, expected.height, width, height);
        free_png_image(&expected);
        return TEST_FAIL;
    }

    for (unsigned y = 0; y < height; y++) {
        for (unsigned x = 0; x < width; x++) {
            uint8_t actual_r, actual_g, actual_b;
            bitmap_pixel_rgb(bitmap[y * width + x], &actual_r, &actual_g, &actual_b);
            uint8_t *expected_pixel = expected.rgb + (y * width + x) * 3;
            if (actual_r != expected_pixel[0] || actual_g != expected_pixel[1] || actual_b != expected_pixel[2]) {
                free_png_image(&expected);
                return TEST_FAIL;
            }
        }
    }

    free_png_image(&expected);
    return TEST_PASS;
}

static test_status_t run_rom(const rom_entry_t *rom, const options_t *options)
{
    if (!rom->has_result_marker && !rom->reference_png_path) {
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
    if (!GB_is_cgb(gb)) {
        GB_set_palette(gb, &docboy_dmg_palette);
    }
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

    uint8_t *hram = NULL;
    if (rom->has_result_marker) {
        size_t hram_size = 0;
        hram = GB_get_direct_access(gb, GB_DIRECT_ACCESS_HRAM, &hram_size, NULL);
        if (!hram || hram_size <= DOCBOY_RESULT_HRAM_OFFSET) {
            GB_free(gb);
            GB_dealloc(gb);
            return TEST_ERROR;
        }

        hram[DOCBOY_RESULT_HRAM_OFFSET] = 0;
    }

    test_status_t result = TEST_UNKNOWN;
    unsigned frames = 0;
    unsigned cycles = 0;
    while (frames < options->timeout_frames) {
        if (rom->has_result_marker) {
            uint8_t marker = hram[DOCBOY_RESULT_HRAM_OFFSET];
            if (marker == 1) {
                result = TEST_PASS;
                break;
            }
            if (marker == 2) {
                result = TEST_FAIL;
                break;
            }
        }

        cycles += GB_run(gb);
        while (cycles >= CYCLES_PER_FRAME) {
            frames++;
            cycles -= CYCLES_PER_FRAME;
        }

        if (!rom->has_result_marker && gb->halted && !gb->interrupt_enable && gb->speed_switch_halt_countdown == 0) {
            break;
        }
    }

    if (result == TEST_UNKNOWN && rom->reference_png_path) {
        result = compare_reference_png(gb, rom->reference_png_path);
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
