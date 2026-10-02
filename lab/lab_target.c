/*
 * Lab target for the CE Testing bridge: a program with values that are known
 * in advance, so the scanner and the signature matcher can be checked against
 * ground truth instead of guesswork.
 *
 * It prints the absolute address of every global it owns, so a test can assert
 * that scan_start/scan_next found exactly the right address.
 *
 * What it provides:
 *   g_health        int,   decremented by the main loop (the classic scan case)
 *   g_mana          float, changed on a different schedule
 *   g_coins         int,   only written when you print status
 *   g_health_copy   int,   a second copy of the health value
 *   g_hidden        int,   a value the player can never see change, for
 *                         checking that a scan does NOT find it
 *   g_sentinel      int,   a fixed marker value
 *   player          struct with health, mana, a name and a position
 *   g_player_ptr    pointer to player, so a pointer chain exists to find
 *   marker()        contains a unique immediate you can AOB scan for
 *   apply_damage()  a real noinline function that writes g_health, so xrefs and
 *                   the disassembler have something honest to find
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <windows.h>

int g_health = 100;
float g_mana = 75.5f;
int g_coins = 1234;
int g_health_copy = 100;
int g_hidden = 987654;
int g_sentinel = 0x11223344;

struct Vec3 {
    float x, y, z;
};

struct Player {
    int health;
    float mana;
    char name[32];
    struct Vec3 position;
    int level;
};

static struct Player player;
static struct Player *g_player_ptr = &player;

__declspec(noinline) int marker(void) {
    /* B8 DE AD BE EF: mov eax, 0xEFBEADDE */
    return 0xEFBEADDE;
}

__declspec(noinline) void apply_damage(int amount) {
    g_health -= amount;
    g_health_copy = g_health;
    if (g_player_ptr) {
        g_player_ptr->health -= amount;
    }
}

__declspec(noinline) void apply_mana(float amount) {
    g_mana += amount;
    if (g_mana < 0.0f) {
        g_mana = 0.0f;
    }
}

static void dump_self(const char *label, const void *fn) {
    const unsigned char *bytes = (const unsigned char *)fn;
    printf("%s_first16=", label);
    for (int i = 0; i < 16; i++) {
        printf("%02X", bytes[i]);
    }
    printf("\n");
}

void print_ground_truth(void) {
    printf("LAB_TARGET_READY\n");
    printf("g_health=%p\n", (void *)&g_health);
    printf("g_mana=%p\n", (void *)&g_mana);
    printf("g_coins=%p\n", (void *)&g_coins);
    printf("g_health_copy=%p\n", (void *)&g_health_copy);
    printf("g_hidden=%p\n", (void *)&g_hidden);
    printf("g_sentinel=%p\n", (void *)&g_sentinel);
    printf("player=%p\n", (void *)&player);
    printf("g_player_ptr=%p\n", (void *)&g_player_ptr);
    printf("marker=%p\n", (void *)marker);
    printf("apply_damage=%p\n", (void *)apply_damage);
    printf("apply_mana=%p\n", (void *)apply_mana);
    printf("sizeof_player=%zu\n", sizeof(struct Player));
    printf("offset_player_health=%zu\n", offsetof(struct Player, health));
    printf("offset_player_mana=%zu\n", offsetof(struct Player, mana));
    printf("offset_player_name=%zu\n", offsetof(struct Player, name));
    printf("offset_player_position=%zu\n", offsetof(struct Player, position));
    printf("offset_player_level=%zu\n", offsetof(struct Player, level));
    dump_self("marker", (const void *)marker);
    dump_self("apply_damage", (const void *)apply_damage);
    printf("LAB_TARGET_END\n");
    fflush(stdout);
}

int main(void) {
    player.health = 100;
    player.mana = 75.5f;
    strcpy(player.name, "lab-player");
    player.position.x = 10.0f;
    player.position.y = 20.0f;
    player.position.z = 30.0f;
    player.level = 1;

    print_ground_truth();

    int ticks = 0;
    int quitting = 0;
    while (!quitting) {
        Sleep(120);
        ticks++;

        if (ticks % 5 == 0) {
            apply_damage(1);
        }
        if (ticks % 7 == 0) {
            apply_mana(-1.0f);
        }
        if (ticks % 50 == 0) {
            g_coins += 10;
            printf("COINS=%d HEALTH=%d MANA=%.1f\n", g_coins, g_health, (double)g_mana);
            fflush(stdout);
        }
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            quitting = 1;
        }
    }

    printf("LAB_TARGET_EXIT health=%d\n", g_health);
    return 0;
}
