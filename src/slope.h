/* slope.h - slope benchmarking framework
 * Copyright © 2013, 2016-2018 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Bench-slopes.
 *
 * Bench-slopes is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Bench-slopes is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SRC_SLOPE_H
#define SRC_SLOPE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>


/*************************************** Default parameters for measurements. */

/* Start at small buffer size, to get reasonable timer calibration for fast
 * implementations (AES-NI etc). Sixteen selected to support the largest block
 * size of current set cipher blocks. */
#define BUF_START_SIZE			16

/* From ~0 to ~4kbytes give comparable results with results from academia
 * (SUPERCOP). */
#define BUF_END_SIZE			(BUF_START_SIZE + 4096)

/* With 128 byte steps, we get (4096)/64 = 64 data points. */
#define BUF_STEP_SIZE			64

/* Number of repeated measurements at each data point. The median of these
 * measurements is selected as data point further analysis. */
#define NUM_MEASUREMENT_REPETITIONS	64


/********************************************** Slope benchmarking framework. */

struct slope_settings
{
  /* CPU Ghz value provided by user, allows constructing cycles/byte and other
    results.  */
  double cpu_ghz;

  /* Attempt to autodetect CPU Ghz. */
  int auto_ghz;

  int csv_mode;
  unsigned int unaligned_mode;
  unsigned int num_measurement_repetitions;

  /* The name of the currently printed section.  */
  char *current_section_name;
  /* The name of the currently printed algorithm.  */
  char *current_algo_name;
  /* The name of the currently printed mode.  */
  char *current_mode_name;
};

struct bench_obj
{
  const struct bench_ops *ops;

  unsigned int min_bufsize;
  unsigned int max_bufsize;
  unsigned int step_size;
  unsigned int num_measurement_repetitions;

  void *priv;
};

typedef int (*const bench_initialize_t) (struct bench_obj * obj);
typedef void (*const bench_finalize_t) (struct bench_obj * obj);
typedef void (*const bench_do_run_t) (struct bench_obj * obj, void *buffer,
				      size_t buflen);

struct bench_ops
{
  bench_initialize_t initialize;
  bench_finalize_t finalize;
  bench_do_run_t do_run;
};


extern struct slope_settings settings;


/* Benchmark and return linear regression slope in nanoseconds per byte.  */
double do_slope_benchmark (struct bench_obj *obj, double *bench_ghz);


/********************************************************** Printing results. */

void double_to_str (char *out, size_t outlen, double value);

void bench_print_result_csv (double nsecs_per_byte, double bench_ghz);

void bench_print_result_std (double nsecs_per_byte, double bench_ghz);

void bench_print_result (double nsecs_per_byte, double bench_ghz);

void bench_print_section (const char *section_name, const char *print_name);

void bench_print_header (int algo_width, const char *algo_name);

void bench_print_algo (int algo_width, const char *algo_name);

void bench_print_mode (int width, const char *mode_name);

void bench_print_footer (int algo_width);

/***************************************************** Main program template. */

struct bench_group
{
  const char *name;
  void (*run)(char **argv, int argc);
};

int
slope_main_template (int argc, char **argv,
		     const struct bench_group *bench_groups,
		     const char *pgm);

#endif /* SRC_SLOPE_H */
