/* slope.c - slope benchmarking framework
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <string.h>

#include "slope.h"

#ifndef STR
#define STR(v) #v
#define STR2(v) STR(v)
#endif


#define AUTO_GHZ_TARGET_DIFF (5e-5)


/* Settings parsed from command-line. */
struct slope_settings settings = { -1, };


static double bench_ghz_diff;


void *rpl_malloc (size_t n)
{
  return malloc (n ? n : 1);
}


/**************************************************** High-resolution timers. */

/* This benchmarking module needs needs high resolution timer.  */
#undef NO_GET_NSEC_TIME
#if defined(_WIN32)
struct nsec_time
{
  LARGE_INTEGER perf_count;
};

static void
get_nsec_time (struct nsec_time *t)
{
  BOOL ok;

  ok = QueryPerformanceCounter (&t->perf_count);
  assert (ok);
}

static double
get_time_nsec_diff (struct nsec_time *start, struct nsec_time *end)
{
  static double nsecs_per_count = 0.0;
  double nsecs;

  if (nsecs_per_count == 0.0)
    {
      LARGE_INTEGER perf_freq;
      BOOL ok;

      /* Get counts per second. */
      ok = QueryPerformanceFrequency (&perf_freq);
      assert (ok);

      nsecs_per_count = 1.0 / perf_freq.QuadPart;
      nsecs_per_count *= 1000000.0 * 1000.0;	/* sec => nsec */

      assert (nsecs_per_count > 0.0);
    }

  nsecs = end->perf_count.QuadPart - start->perf_count.QuadPart;	/* counts */
  nsecs *= nsecs_per_count;	/* counts * (nsecs / count) => nsecs */

  return nsecs;
}
#elif defined(HAVE_CLOCK_GETTIME)
struct nsec_time
{
  struct timespec ts;
};

static void
get_nsec_time (struct nsec_time *t)
{
  int err;

  err = clock_gettime (CLOCK_REALTIME, &t->ts);
  assert (err == 0);
}

static double
get_time_nsec_diff (struct nsec_time *start, struct nsec_time *end)
{
  double nsecs;

  nsecs = end->ts.tv_sec - start->ts.tv_sec;
  nsecs *= 1000000.0 * 1000.0;	/* sec => nsec */

  /* This way we don't have to care if tv_nsec unsigned or signed. */
  if (end->ts.tv_nsec >= start->ts.tv_nsec)
    nsecs += end->ts.tv_nsec - start->ts.tv_nsec;
  else
    nsecs -= start->ts.tv_nsec - end->ts.tv_nsec;

  return nsecs;
}
#elif defined(HAVE_GETTIMEOFDAY)
struct nsec_time
{
  struct timeval tv;
};

static void
get_nsec_time (struct nsec_time *t)
{
  int err;

  err = gettimeofday (&t->tv, NULL);
  assert (err == 0);
}

static double
get_time_nsec_diff (struct nsec_time *start, struct nsec_time *end)
{
  double nsecs;

  nsecs = end->tv.tv_sec - start->tv.tv_sec;
  nsecs *= 1000000;		/* sec => µsec */

  /* This way we don't have to care if tv_usec unsigned or signed. */
  if (end->tv.tv_usec >= start->tv.tv_usec)
    nsecs += end->tv.tv_usec - start->tv.tv_usec;
  else
    nsecs -= start->tv.tv_usec - end->tv.tv_usec;

  nsecs *= 1000;		/* µsec => nsec */

  return nsecs;
}
#else
#define NO_GET_NSEC_TIME 1
#endif


/* If no high resolution timer found, provide dummy bench-slope.  */
#ifdef NO_GET_NSEC_TIME


static double
slope_benchmark (struct bench_obj *obj)
{
#warning "no high resolution timer found!"
  return 0.0;
}


#else /* !NO_GET_NSEC_TIME */


/********************************************** Slope benchmarking framework. */


static double
get_slope (double (*const get_x) (unsigned int idx, void *priv),
	   void *get_x_priv, double y_points[], unsigned int npoints,
	   double *overhead)
{
  double sumx, sumy, sumx2, sumy2, sumxy;
  unsigned int i;
  double b, a;

  sumx = sumy = sumx2 = sumy2 = sumxy = 0;

  for (i = 0; i < npoints; i++)
    {
      double x, y;

      x = get_x (i, get_x_priv);	/* bytes */
      y = y_points[i];		/* nsecs */

      sumx += x;
      sumy += y;
      sumx2 += x * x;
      /*sumy2 += y * y;*/
      sumxy += x * y;
    }

  b = (npoints * sumxy - sumx * sumy) / (npoints * sumx2 - sumx * sumx);
  a = (sumy - b * sumx) / npoints;

  if (overhead)
    *overhead = a;		/* nsecs */

  return b;			/* nsecs per byte */
}


static double
get_bench_obj_point_x (unsigned int idx, void *priv)
{
  struct bench_obj *obj = priv;
  return (double) (obj->min_bufsize + (idx * obj->step_size));
}


static unsigned int
get_num_measurements (struct bench_obj *obj)
{
  unsigned int buf_range = obj->max_bufsize - obj->min_bufsize;
  unsigned int num = buf_range / obj->step_size + 1;

  while (obj->min_bufsize + (num * obj->step_size) > obj->max_bufsize)
    num--;

  return num + 1;
}


static int
double_cmp (const void *_a, const void *_b)
{
  const double *a, *b;

  a = _a;
  b = _b;

  if (*a > *b)
    return 1;
  if (*a < *b)
    return -1;
  return 0;
}


static double
do_bench_obj_measurement (struct bench_obj *obj, void *buffer, size_t buflen,
			  double *measurement_raw,
			  unsigned int loop_iterations)
{
  unsigned int num_repetitions = obj->num_measurement_repetitions;
  const bench_do_run_t do_run = obj->ops->do_run;
  struct nsec_time start, end;
  unsigned int rep, loop;
  double res;

  if (num_repetitions == 0)
    num_repetitions = settings.num_measurement_repetitions;

  if (num_repetitions < 1 || loop_iterations < 1)
    return 0.0;

  for (rep = 0; rep < num_repetitions; rep++)
    {
      get_nsec_time (&start);

      for (loop = 0; loop < loop_iterations; loop++)
	do_run (obj, buffer, buflen);

      get_nsec_time (&end);

      measurement_raw[rep] = get_time_nsec_diff (&start, &end);
    }

  /* Return median of repeated measurements. */
  qsort (measurement_raw, num_repetitions, sizeof (measurement_raw[0]),
	 double_cmp);

  if (num_repetitions % 2 == 1)
    return measurement_raw[num_repetitions / 2];

  res = measurement_raw[num_repetitions / 2]
    + measurement_raw[num_repetitions / 2 - 1];
  return res / 2;
}


static unsigned int
adjust_loop_iterations_to_timer_accuracy (struct bench_obj *obj, void *buffer,
					  double *measurement_raw)
{
  const double increase_thres = 3.0;
  double tmp, nsecs;
  unsigned int loop_iterations;
  unsigned int test_bufsize;

  test_bufsize = obj->min_bufsize;
  if (test_bufsize == 0)
    test_bufsize += obj->step_size;

  loop_iterations = 0;
  do
    {
      /* Increase loop iterations until we get other results than zero.  */
      nsecs =
	do_bench_obj_measurement (obj, buffer, test_bufsize,
				  measurement_raw, ++loop_iterations);
    }
  while (nsecs < 1.0 - 0.1);
  do
    {
      /* Increase loop iterations until we get reasonable increase for elapsed time.  */
      tmp =
	do_bench_obj_measurement (obj, buffer, test_bufsize,
				  measurement_raw, ++loop_iterations);
    }
  while (tmp < nsecs * (increase_thres - 0.1));

  return loop_iterations;
}


/* Benchmark and return linear regression slope in nanoseconds per byte.  */
static double
slope_benchmark (struct bench_obj *obj)
{
  unsigned int num_repetitions;
  unsigned int num_measurements;
  double *measurements = NULL;
  double *measurement_raw = NULL;
  double slope, overhead;
  unsigned int loop_iterations, midx, i;
  unsigned char *real_buffer = NULL;
  unsigned char *buffer;
  size_t cur_bufsize;
  int err;

  err = obj->ops->initialize (obj);
  if (err < 0)
    return -1;

  num_repetitions = obj->num_measurement_repetitions;
  if (num_repetitions == 0)
    num_repetitions = settings.num_measurement_repetitions;

  num_measurements = get_num_measurements (obj);
  measurements = calloc (num_measurements, sizeof (*measurements));
  if (!measurements)
    goto err_free;

  measurement_raw = calloc (num_repetitions, sizeof (*measurement_raw));
  if (!measurement_raw)
    goto err_free;

  if (num_measurements < 1 || num_repetitions < 1 || obj->max_bufsize < 1 ||
      obj->min_bufsize > obj->max_bufsize)
    goto err_free;

  real_buffer = malloc (obj->max_bufsize + 128 + settings.unaligned_mode);
  if (!real_buffer)
    goto err_free;
  /* Get aligned buffer */
  buffer = real_buffer;
  buffer += 128 - ((real_buffer - (unsigned char *) 0) & (128 - 1));
  if (settings.unaligned_mode)
    buffer += settings.unaligned_mode; /* Make buffer unaligned */

  for (i = 0; i < obj->max_bufsize; i++)
    buffer[i] = 0x55 ^ (-i);

  /* Adjust number of loop iterations up to timer accuracy.  */
  loop_iterations = adjust_loop_iterations_to_timer_accuracy (obj, buffer,
							      measurement_raw);

  /* Perform measurements */
  for (midx = 0, cur_bufsize = obj->min_bufsize;
       cur_bufsize <= obj->max_bufsize; cur_bufsize += obj->step_size, midx++)
    {
      measurements[midx] =
	do_bench_obj_measurement (obj, buffer, cur_bufsize, measurement_raw,
				  loop_iterations);
      measurements[midx] /= loop_iterations;
    }

  assert (midx == num_measurements);

  slope =
    get_slope (&get_bench_obj_point_x, obj, measurements, num_measurements,
	       &overhead);

  free (measurement_raw);
  free (measurements);
  free (real_buffer);
  obj->ops->finalize (obj);

  return slope;

err_free:
  if (measurement_raw)
    free (measurement_raw);
  if (measurements)
    free (measurements);
  if (real_buffer)
    free (real_buffer);
  obj->ops->finalize (obj);

  return -1;
}


#endif /* !NO_GET_NSEC_TIME */


/********************************************* CPU frequency auto-detection. */

static int
auto_ghz_init (struct bench_obj *obj)
{
  obj->min_bufsize = 16;
  obj->max_bufsize = 64 + obj->min_bufsize;
  obj->step_size = 8;
  obj->num_measurement_repetitions = 16;

  return 0;
}

static void
auto_ghz_free (struct bench_obj *obj)
{
  (void)obj;
}

static void
auto_ghz_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  (void)obj;
  (void)buf;

  buflen *= 1024;

  /* Turbo frequency detection benchmark. Without CPU turbo-boost, this
   * function will give cycles/iteration result 1024.0 on high-end CPUs.
   * With turbo, result will be less and can be used detect turbo-clock. */

  do
    {
      /* Use memory barrier to prevent compiler from optimizing this loop
       * away. */

      asm volatile ("":::"memory");
    }
  while (--buflen);
}

static struct bench_ops auto_ghz_detect_ops = {
  &auto_ghz_init,
  &auto_ghz_free,
  &auto_ghz_bench
};


double
get_auto_ghz (void)
{
  struct bench_obj obj = { 0 };
  double nsecs_per_iteration;
  double cycles_per_iteration;

  obj.ops = &auto_ghz_detect_ops;

  nsecs_per_iteration = slope_benchmark (&obj);

  cycles_per_iteration = nsecs_per_iteration * settings.cpu_ghz;

  /* Adjust CPU Ghz so that cycles per iteration would give '1024.0'. */

  return settings.cpu_ghz * 1024 / cycles_per_iteration;
}


double
do_slope_benchmark (struct bench_obj *obj, double *bench_ghz)
{
  double ret;

  if (!settings.auto_ghz)
    {
      /* Perform measurement without autodetection of CPU frequency. */

      ret = slope_benchmark (obj);

      *bench_ghz = settings.cpu_ghz;
    }
  else
    {
      double target_diff = AUTO_GHZ_TARGET_DIFF;
      double cpu_auto_ghz_before;
      double cpu_auto_ghz_after;
      double nsecs_per_iteration;
      double diff;
      unsigned int try_count = 0;

      /* Perform measurement with CPU frequency autodetection. */

      do
        {
          /* Repeat measurement until CPU turbo frequency has stabilized. */

	  if (try_count++ > 4)
	    {
	      /* Too much frequency instability on the system, relax target
	       * accuracy. */

	      try_count = 0;
	      target_diff *= 2;
	    }

          cpu_auto_ghz_before = get_auto_ghz ();

          nsecs_per_iteration = slope_benchmark (obj);

          cpu_auto_ghz_after = get_auto_ghz ();

          diff = 1.0 - (cpu_auto_ghz_before / cpu_auto_ghz_after);
          diff = diff < 0 ? -diff : diff;
        }
      while (diff > target_diff);

      ret = nsecs_per_iteration;

      *bench_ghz = cpu_auto_ghz_after;
      bench_ghz_diff = diff;
    }

  return ret;
}


/********************************************************** Printing results. */

void
double_to_str (char *out, size_t outlen, double value)
{
  const char *fmt;

  if (value < 1.0)
    fmt = "%.3f";
  else if (value < 100.0)
    fmt = "%.2f";
  else
    fmt = "%.1f";

  snprintf (out, outlen, fmt, value);
}

void
bench_print_result_csv (double nsecs_per_byte, double bench_ghz)
{
  double cycles_per_byte, mbytes_per_sec;
  char nsecpbyte_buf[16];
  char mbpsec_buf[16];
  char cpbyte_buf[16];
  char mhz_buf[16];
  char mhz_diff_buf[32];

  strcpy (mhz_diff_buf, "");

  *cpbyte_buf = 0;

  double_to_str (nsecpbyte_buf, sizeof (nsecpbyte_buf), nsecs_per_byte);

  /* If user didn't provide CPU speed, we cannot show cycles/byte results.  */
  if (bench_ghz > 0.0)
    {
      cycles_per_byte = nsecs_per_byte * bench_ghz;
      double_to_str (cpbyte_buf, sizeof (cpbyte_buf), cycles_per_byte);
      double_to_str (mhz_buf, sizeof (mhz_buf), bench_ghz * 1000);
      if (settings.auto_ghz && bench_ghz_diff * 1000 >= 0.1)
	{
	  snprintf(mhz_diff_buf, sizeof(mhz_diff_buf), ",%.1f,Mhz-diff",
		   bench_ghz_diff * 1000);
	}
    }

  mbytes_per_sec =
    (1000.0 * 1000.0 * 1000.0) / (nsecs_per_byte * 1024 * 1024);
  double_to_str (mbpsec_buf, sizeof (mbpsec_buf), mbytes_per_sec);

  /* We print two empty fields to allow for future enhancements.  */
  if (settings.auto_ghz)
    {
      printf ("%s,%s,%s,,,%s,ns/B,%s,MiB/s,%s,c/B,%s,Mhz%s\n",
              settings.current_section_name,
              settings.current_algo_name ? settings.current_algo_name : "",
              settings.current_mode_name ? settings.current_mode_name : "",
              nsecpbyte_buf,
              mbpsec_buf,
              cpbyte_buf,
              mhz_buf,
	      mhz_diff_buf);
    }
  else
    {
      printf ("%s,%s,%s,,,%s,ns/B,%s,MiB/s,%s,c/B\n",
              settings.current_section_name,
              settings.current_algo_name ? settings.current_algo_name : "",
              settings.current_mode_name ? settings.current_mode_name : "",
              nsecpbyte_buf,
              mbpsec_buf,
              cpbyte_buf);
    }
}

void
bench_print_result_std (double nsecs_per_byte, double bench_ghz)
{
  double cycles_per_byte, mbytes_per_sec;
  char nsecpbyte_buf[16];
  char mbpsec_buf[16];
  char cpbyte_buf[16];
  char mhz_buf[16];
  char mhz_diff_buf[16];

  strcpy (mhz_diff_buf, "");

  double_to_str (nsecpbyte_buf, sizeof (nsecpbyte_buf), nsecs_per_byte);

  /* If user didn't provide CPU speed, we cannot show cycles/byte results.  */
  if (bench_ghz > 0.0)
    {
      cycles_per_byte = nsecs_per_byte * bench_ghz;
      double_to_str (cpbyte_buf, sizeof (cpbyte_buf), cycles_per_byte);
      double_to_str (mhz_buf, sizeof (mhz_buf), bench_ghz * 1000);
      if (settings.auto_ghz && bench_ghz_diff * 1000 >= 0.1)
	{
	  snprintf(mhz_diff_buf, sizeof(mhz_diff_buf), "±%.1f",
		   bench_ghz_diff * 1000);
	}
    }
  else
    {
      strcpy (cpbyte_buf, "-");
      strcpy (mhz_buf, "-");
    }

  mbytes_per_sec =
    (1000.0 * 1000.0 * 1000.0) / (nsecs_per_byte * 1024 * 1024);
  double_to_str (mbpsec_buf, sizeof (mbpsec_buf), mbytes_per_sec);

  if (settings.auto_ghz)
    {
      printf ("%9s ns/B %9s MiB/s %9s c/B %9s%s\n",
              nsecpbyte_buf, mbpsec_buf, cpbyte_buf, mhz_buf,mhz_diff_buf);
    }
  else
    {
      printf ("%9s ns/B %9s MiB/s %9s c/B\n",
              nsecpbyte_buf, mbpsec_buf, cpbyte_buf);
    }
}

void
bench_print_result (double nsecs_per_byte, double bench_ghz)
{
  if (settings.csv_mode)
    bench_print_result_csv (nsecs_per_byte, bench_ghz);
  else
    bench_print_result_std (nsecs_per_byte, bench_ghz);
}

void
bench_print_section (const char *section_name, const char *print_name)
{
  if (settings.csv_mode)
    {
      free (settings.current_section_name);
      settings.current_section_name = strdup (section_name);
    }
  else
    printf ("%s:\n", print_name);
}

void
bench_print_header (int algo_width, const char *algo_name)
{
  if (settings.csv_mode)
    {
      free (settings.current_algo_name);
      settings.current_algo_name = strdup (algo_name);
    }
  else
    {
      if (algo_width < 0)
        printf (" %-*s | ", -algo_width, algo_name);
      else
        printf (" %-*s | ", algo_width, algo_name);

      if (settings.auto_ghz)
        printf ("%14s %15s %13s %9s\n", "nanosecs/byte", "mebibytes/sec",
                "cycles/byte", "auto Mhz");
      else
        printf ("%14s %15s %13s\n", "nanosecs/byte", "mebibytes/sec",
                "cycles/byte");
    }
}

void
bench_print_algo (int algo_width, const char *algo_name)
{
  if (settings.csv_mode)
    {
      free (settings.current_algo_name);
      settings.current_algo_name = strdup (algo_name);
    }
  else
    {
      if (algo_width < 0)
        printf (" %-*s | ", -algo_width, algo_name);
      else
        printf (" %-*s | ", algo_width, algo_name);
    }
}

void
bench_print_mode (int width, const char *mode_name)
{
  if (settings.csv_mode)
    {
      free (settings.current_mode_name);
      settings.current_mode_name = strdup (mode_name);
    }
  else
    {
      if (width < 0)
        printf (" %-*s | ", -width, mode_name);
      else
        printf (" %*s | ", width, mode_name);
      fflush (stdout);
    }
}

void
bench_print_footer (int algo_width)
{
  if (!settings.csv_mode)
    printf (" %-*s =\n", algo_width, "");
}


/***************************************************** Main program template. */


static void
print_help (const struct bench_group *bench_groups, const char *pgm)
{
  static const char *help_lines[] = {
    "",
    " options:",
    "   --cpu-mhz <mhz>           Set CPU speed for calculating cycles",
    "                             per bytes results.  Set as \"auto\"",
    "                             for auto-detection of CPU speed.",
    "   --repetitions <n>         Use N repetitions (default "
                                     STR2(NUM_MEASUREMENT_REPETITIONS) ")",
    "   --unaligned               Use unaligned input buffers.",
    "   --csv                     Use CSV output format",
    NULL
  };
  const char **line;
  const struct bench_group *group;

  fprintf (stdout, "usage: %s [options] [", pgm);
  for (group = bench_groups; group && group->name; ++group)
    fprintf (stdout, "%s%s", group->name, (group + 1)->name ? "|" : "]\n");

  for (line = help_lines; *line; line++)
    fprintf (stdout, "%s\n", *line);
}


/* Warm up CPU.  */
static void
warm_up_cpu (void)
{
#ifndef NO_GET_NSEC_TIME
  struct nsec_time start, end;

  get_nsec_time (&start);
  do
    {
      get_nsec_time (&end);
    }
  while (get_time_nsec_diff (&start, &end) < 1000.0 * 1000.0 * 1000.0);
#endif /* !NO_GET_NSEC_TIME */
}


int
slope_main_template (int argc, char **argv,
		     const struct bench_group *bench_groups,
		     const char *pgm)
{
  const struct bench_group *group;
  int last_argc = -1;
  int debug = 0;

  if (argc)
    {
      argc--;
      argv++;
    }

  settings.num_measurement_repetitions = NUM_MEASUREMENT_REPETITIONS;

  while (argc && last_argc != argc)
    {
      last_argc = argc;

      if (!strcmp (*argv, "--"))
	{
	  argc--;
	  argv++;
	  break;
	}
      else if (!strcmp (*argv, "--help"))
	{
	  print_help (bench_groups, pgm);
	  exit (0);
	}
      else if (!strcmp (*argv, "--csv"))
	{
	  settings.csv_mode = 1;
	  argc--;
	  argv++;
	}
      else if (!strcmp (*argv, "--unaligned"))
	{
	  settings.unaligned_mode = 1;
	  argc--;
	  argv++;
	}
      else if (!strcmp (*argv, "--cpu-mhz"))
	{
	  argc--;
	  argv++;
	  if (argc)
	    {
              if (!strcmp (*argv, "auto"))
                {
                  settings.auto_ghz = 1;
                }
              else
                {
                  settings.cpu_ghz = atof (*argv);
                  settings.cpu_ghz /= 1000;	/* Mhz => Ghz */
                }

	      argc--;
	      argv++;
	    }
	}
      else if (!strcmp (*argv, "--repetitions"))
	{
	  argc--;
	  argv++;
	  if (argc)
	    {
	      settings.num_measurement_repetitions = atof (*argv);
	      if (settings.num_measurement_repetitions < 2)
		{
		  fprintf (stderr,
			  "%s: value for --repetitions too small - using %d\n",
			  pgm, NUM_MEASUREMENT_REPETITIONS);
		  settings.num_measurement_repetitions =
		    NUM_MEASUREMENT_REPETITIONS;
		}
	      argc--;
	      argv++;
	    }
	}
    }

  if (!argc)
    {
      warm_up_cpu ();
      for (group = bench_groups; group && group->name; ++group)
	group->run (NULL, 0);
    }
  else
    {
      for (group = bench_groups; group && group->name; ++group)
	{
	  if (!strcmp (*argv, group->name))
	    {
	      argc--;
	      argv++;

	      warm_up_cpu ();
	      group->run ((argc == 0) ? NULL : argv, argc);

	      break;
	    }
	}

      if (!group || !group->name)
	{
	  fprintf (stderr, "%s: unknown argument: %s\n", pgm, *argv);
	  print_help (bench_groups, pgm);
	}
    }

  return 0;
}
