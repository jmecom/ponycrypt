#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t (*ponycrypt_dudect_callback_t)(uint8_t *data);

static ponycrypt_dudect_callback_t ponycrypt_dudect_callback = 0;

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

uint8_t do_one_computation(uint8_t *data) {
  return ponycrypt_dudect_callback(data);
}

uint8_t ponycrypt_dudect_input_byte(uint8_t *data, size_t index) {
  return data[index];
}

void prepare_inputs(
  dudect_config_t *c,
  uint8_t *input_data,
  uint8_t *classes) {
  randombytes(input_data, c->number_measurements * c->chunk_size);

  for (size_t i = 0; i < c->number_measurements; i++) {
    classes[i] = randombit();

    if (classes[i] == 0) {
      memset(input_data + (i * c->chunk_size), 0x00, c->chunk_size);
    }
  }
}

int ponycrypt_dudect_run(
  ponycrypt_dudect_callback_t callback,
  size_t max_chunks,
  size_t number_measurements,
  size_t chunk_size) {
  ponycrypt_dudect_callback = callback;

  dudect_config_t config = {
    .chunk_size = chunk_size,
    .number_measurements = number_measurements,
  };
  dudect_ctx_t ctx;

  if (dudect_init(&ctx, &config) != 0) {
    fprintf(stderr, "dudect_init failed\n");
    return 0;
  }

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  size_t chunks = 0;

  while ((state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) &&
         (chunks < max_chunks)) {
    state = dudect_main(&ctx);
    chunks++;
  }

  if (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    printf(
      "Reached max_chunks=%zu without leakage evidence.\n",
      max_chunks);
  }

  dudect_free(&ctx);
  return (int)state;
}
