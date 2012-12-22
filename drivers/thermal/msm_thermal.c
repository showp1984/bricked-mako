/* Copyright (c) 2012, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/mutex.h>
#include <linux/msm_tsens.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/reboot.h>
#include <linux/earlysuspend.h>

#define DEF_TEMP_SENSOR0      0
#define DEF_TEMP_SENSOR1      1

//shutdown temp
#define DEF_SHUTDOWNTEMP 80

//max thermal limit
#define DEF_ALLOWED_MAX_HIGH 75
#define DEF_ALLOWED_MAX_FREQ 384000

//mid thermal limit
#define DEF_ALLOWED_MID_HIGH 72
#define DEF_ALLOWED_MID_FREQ 810000

//low thermal limit
#define DEF_ALLOWED_LOW_HIGH 70
#define DEF_ALLOWED_LOW_FREQ 1350000

//Sampling interval
#define DEF_THERMAL_CHECK_MS 100

static DEFINE_MUTEX(emergency_shutdown_mutex);

static int enabled;

//Throttling indicator, 0=not throttled, 1=low, 2=mid, 3=max
static int thermal_throttled = 0;

//Save the cpu max freq before throttling
static int pre_throttled_max = 0;

//screen status
static bool screen_blank = false;

static struct delayed_work check_temp_work;
static struct workqueue_struct *check_temp_workq;

static struct msm_thermal_tuners {
	unsigned int shutdown_temp;

	unsigned int allowed_max_high;
	unsigned int allowed_max_low;
	unsigned int allowed_max_freq;

	unsigned int allowed_mid_high;
	unsigned int allowed_mid_low;
	unsigned int allowed_mid_freq;

	unsigned int allowed_low_high;
	unsigned int allowed_low_low;
	unsigned int allowed_low_freq;

	unsigned int check_interval_ms;
} msm_thermal_tuners_ins = {
	.shutdown_temp = DEF_SHUTDOWNTEMP,

	.allowed_max_high = DEF_ALLOWED_MAX_HIGH,
	.allowed_max_low = (DEF_ALLOWED_MAX_HIGH - 4),
	.allowed_max_freq = DEF_ALLOWED_MAX_FREQ,

	.allowed_mid_high = DEF_ALLOWED_MID_HIGH,
	.allowed_mid_low = (DEF_ALLOWED_MID_HIGH - 5),
	.allowed_mid_freq = DEF_ALLOWED_MID_FREQ,

	.allowed_low_high = DEF_ALLOWED_LOW_HIGH,
	.allowed_low_low = (DEF_ALLOWED_LOW_HIGH - 6),
	.allowed_low_freq = DEF_ALLOWED_LOW_FREQ,

	.check_interval_ms = DEF_THERMAL_CHECK_MS,
};

static int update_cpu_max_freq(struct cpufreq_policy *cpu_policy,
			       int cpu, int max_freq)
{
	int ret = 0;

	if (!cpu_policy)
		return -EINVAL;

	cpufreq_verify_within_limits(cpu_policy,
				cpu_policy->min, max_freq);
	cpu_policy->user_policy.max = max_freq;

	ret = cpufreq_update_policy(cpu);
	if (!ret)
		pr_debug("msm_thermal: Setting CPU%d max frequency to %d\n",
			cpu, max_freq);
	return ret;
}

static void check_temp(struct work_struct *work)
{
	struct cpufreq_policy *cpu_policy = NULL;
	struct tsens_device tsens_dev0;
	struct tsens_device tsens_dev1;
	unsigned long temp = 0, temp0 = 0, temp1 = 0;
	unsigned int max_freq = 0;
	bool update_policy = false;
	int i = 0, cpu = 0;
	int ret0 = 0, ret1 = 0;
        bool sensor_fail = false;

	tsens_dev0.sensor_num = DEF_TEMP_SENSOR0;
	ret0 = tsens_get_temp(&tsens_dev0, &temp0);
	tsens_dev1.sensor_num = DEF_TEMP_SENSOR1;
	ret1 = tsens_get_temp(&tsens_dev1, &temp1);
	if (ret0 && ret1) {
		pr_err("msm_thermal: FATAL: Unable to read TSENS sensor %d & %d\n",
				tsens_dev0.sensor_num, tsens_dev1.sensor_num);
		goto reschedule;
	}

        if ((screen_blank) || (temp1 < 0) || (temp1 > 150)) {
                sensor_fail = true;
                temp = temp0;
        } else {
                sensor_fail = false;
                temp = (max(temp0, temp1));
        }

        if (temp >= msm_thermal_tuners_ins.shutdown_temp) {
                mutex_lock(&emergency_shutdown_mutex);
                pr_warn("################################\n");
                pr_warn("################################\n");
                pr_warn("- %u OVERTEMP! SHUTTING DOWN! -\n", msm_thermal_tuners_ins.shutdown_temp);
                pr_warn("- cur temp:%lu measured by:%s -\n", temp, ((sensor_fail) || (temp0>temp1)) ? "0" : "1");
                pr_warn("################################\n");
                pr_warn("################################\n");
                /* orderly poweroff tries to power down gracefully
                   if it fails it will force it. */
                orderly_poweroff(true);
                for_each_possible_cpu(cpu) {
                        update_policy = true;
                        max_freq = msm_thermal_tuners_ins.allowed_max_freq;
                        thermal_throttled = 3;
                        pr_warn("msm_thermal: Emergency throttled CPU%i to %u! temp:%lu\n",
                                cpu, msm_thermal_tuners_ins.allowed_max_freq, temp);
                }
                mutex_unlock(&emergency_shutdown_mutex);
        }

	for_each_possible_cpu(cpu) {
		update_policy = false;
		cpu_policy = cpufreq_cpu_get(cpu);
		if (!cpu_policy) {
			pr_debug("msm_thermal: NULL policy on cpu %d\n", cpu);
			continue;
		}

		/* save pre-throttled max freq value */
                if ((thermal_throttled == 0) && (cpu == 0))
                        pre_throttled_max = cpu_policy->max;

		//low trip point
		if ((temp >= msm_thermal_tuners_ins.allowed_low_high) &&
		    (temp < msm_thermal_tuners_ins.allowed_mid_high) &&
                    (thermal_throttled < 1)) {
			update_policy = true;
			max_freq = msm_thermal_tuners_ins.allowed_low_freq;
                        if (cpu == (CONFIG_NR_CPUS-1)) {
                                thermal_throttled = 1;
                                pr_warn("msm_thermal: Thermal Throttled (low)! temp:%lu by:%s\n",
                                        temp, ((sensor_fail) || (temp0>temp1)) ? "0" : "1");
                        }
		//low clr point
		} else if ((temp < msm_thermal_tuners_ins.allowed_low_low) &&
			   (thermal_throttled > 0)) {
			if (pre_throttled_max != 0)
				max_freq = pre_throttled_max;
			else {
				max_freq = CONFIG_MSM_CPU_FREQ_MAX;
				pr_warn("msm_thermal: ERROR! pre_throttled_max=0, falling back to %u\n", max_freq);
			}
			update_policy = true;
                        for (i = 1; i < CONFIG_NR_CPUS; i++) {
                                if (cpu_online(i))
                                        continue;
                                cpu_up(i);
                        }
                        if (cpu == (CONFIG_NR_CPUS-1)) {
                                thermal_throttled = 0;
                                pr_warn("msm_thermal: Low thermal throttle ended! temp:%lu by:%s\n",
                                        temp, ((sensor_fail) || (temp0>temp1)) ? "0" : "1");
                        }
		//mid trip point
		} else if ((temp >= msm_thermal_tuners_ins.allowed_mid_high) &&
			   (temp < msm_thermal_tuners_ins.allowed_max_high) &&
			   (thermal_throttled < 2)) {
			update_policy = true;
			max_freq = msm_thermal_tuners_ins.allowed_mid_freq;
                        if (cpu == (CONFIG_NR_CPUS-1)) {
                                thermal_throttled = 2;
                                pr_warn("msm_thermal: Thermal Throttled (mid)! temp:%lu by:%s\n",
                                        temp, ((sensor_fail) || (temp0>temp1)) ? "0" : "1");
                        }
		//mid clr point
		} else if ((temp < msm_thermal_tuners_ins.allowed_mid_low) &&
			   (thermal_throttled > 1)) {
			max_freq = msm_thermal_tuners_ins.allowed_low_freq;
			update_policy = true;
                        if (cpu == (CONFIG_NR_CPUS-1)) {
                                thermal_throttled = 1;
                                pr_warn("msm_thermal: Mid thermal throttle ended! temp:%lu by:%s\n",
                                        temp, ((sensor_fail) || (temp0>temp1)) ? "0" : "1");
                        }
		//max trip point
		} else if (temp >= msm_thermal_tuners_ins.allowed_max_high) {
			update_policy = true;
			max_freq = msm_thermal_tuners_ins.allowed_max_freq;
                        if (cpu == (CONFIG_NR_CPUS-1)) {
			        thermal_throttled = 3;
                                pr_warn("msm_thermal: Thermal Throttled (max)! temp:%lu by:%s\n",
                                        temp, ((sensor_fail) || (temp0>temp1)) ? "0" : "1");
                        }
		//max clr point
		} else if ((temp < msm_thermal_tuners_ins.allowed_max_low) &&
			   (thermal_throttled > 2)) {
			max_freq = msm_thermal_tuners_ins.allowed_mid_freq;
			update_policy = true;
                        if (cpu == (CONFIG_NR_CPUS-1)) {
                                thermal_throttled = 2;
                                pr_warn("msm_thermal: Max thermal throttle ended! temp:%lu by:%s\n",
                                        temp, ((sensor_fail) || (temp0>temp1)) ? "0" : "1");
                        }
		}

		if (update_policy)
			update_cpu_max_freq(cpu_policy, cpu, max_freq);

		cpufreq_cpu_put(cpu_policy);
	}

reschedule:
	if (enabled)
		queue_delayed_work(check_temp_workq, &check_temp_work,
				msecs_to_jiffies(msm_thermal_tuners_ins.check_interval_ms));
        return;
}

static void disable_msm_thermal(void)
{
	int cpu = 0;
	struct cpufreq_policy *cpu_policy = NULL;

	/* make sure check_temp is no longer running */
	cancel_delayed_work_sync(&check_temp_work);
	flush_scheduled_work();

	for_each_possible_cpu(cpu) {
		cpu_policy = cpufreq_cpu_get(cpu);
		if (cpu_policy) {
			if (cpu_policy->max < cpu_policy->cpuinfo.max_freq)
				update_cpu_max_freq(cpu_policy, cpu,
						    cpu_policy->
						    cpuinfo.max_freq);
			cpufreq_cpu_put(cpu_policy);
		}
	}
}

static int set_enabled(const char *val, const struct kernel_param *kp)
{
	int ret = 0;

	ret = param_set_bool(val, kp);
	if (!enabled)
		disable_msm_thermal();
	else
		pr_info("msm_thermal: no action for enabled = %d\n", enabled);

	pr_info("msm_thermal: enabled = %d\n", enabled);

	return ret;
}

static struct kernel_param_ops module_ops = {
	.set = set_enabled,
	.get = param_get_bool,
};

module_param_cb(enabled, &module_ops, &enabled, 0644);
MODULE_PARM_DESC(enabled, "enforce thermal limit on cpu");

/**************************** SYSFS START ****************************/
struct kobject *msm_thermal_kobject;

#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)               \
{									\
	return sprintf(buf, "%u\n", msm_thermal_tuners_ins.object);				\
}

show_one(shutdown_temp, shutdown_temp);
show_one(allowed_max_high, allowed_max_high);
show_one(allowed_max_low, allowed_max_low);
show_one(allowed_max_freq, allowed_max_freq);
show_one(allowed_mid_high, allowed_mid_high);
show_one(allowed_mid_low, allowed_mid_low);
show_one(allowed_mid_freq, allowed_mid_freq);
show_one(allowed_low_high, allowed_low_high);
show_one(allowed_low_low, allowed_low_low);
show_one(allowed_low_freq, allowed_low_freq);
show_one(check_interval_ms, check_interval_ms);

static ssize_t store_shutdown_temp(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.shutdown_temp = input;

	return count;
}

static ssize_t store_allowed_max_high(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_max_high = input;

	return count;
}

static ssize_t store_allowed_max_low(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_max_low = input;

	return count;
}

static ssize_t store_allowed_max_freq(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_max_freq = input;

	return count;
}

static ssize_t store_allowed_mid_high(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_mid_high = input;

	return count;
}

static ssize_t store_allowed_mid_low(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_mid_low = input;

	return count;
}

static ssize_t store_allowed_mid_freq(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_mid_freq = input;

	return count;
}

static ssize_t store_allowed_low_high(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_low_high = input;

	return count;
}

static ssize_t store_allowed_low_low(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_low_low = input;

	return count;
}

static ssize_t store_allowed_low_freq(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_low_freq = input;

	return count;
}

static ssize_t store_check_interval_ms(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.check_interval_ms = input;

	return count;
}

define_one_global_rw(shutdown_temp);
define_one_global_rw(allowed_max_high);
define_one_global_rw(allowed_max_low);
define_one_global_rw(allowed_max_freq);
define_one_global_rw(allowed_mid_high);
define_one_global_rw(allowed_mid_low);
define_one_global_rw(allowed_mid_freq);
define_one_global_rw(allowed_low_high);
define_one_global_rw(allowed_low_low);
define_one_global_rw(allowed_low_freq);
define_one_global_rw(check_interval_ms);

static struct attribute *msm_thermal_attributes[] = {
        &shutdown_temp.attr,
	&allowed_max_high.attr,
	&allowed_max_low.attr,
	&allowed_max_freq.attr,
	&allowed_mid_high.attr,
	&allowed_mid_low.attr,
	&allowed_mid_freq.attr,
	&allowed_low_high.attr,
	&allowed_low_low.attr,
	&allowed_low_freq.attr,
	&check_interval_ms.attr,
	NULL
};


static struct attribute_group msm_thermal_attr_group = {
	.attrs = msm_thermal_attributes,
	.name = "conf",
};
/**************************** SYSFS END ****************************/

static void msm_thermal_early_suspend(struct early_suspend *h)
{
        screen_blank = true;
}

static void msm_thermal_late_resume(struct early_suspend *h)
{
        screen_blank = false;
}

static struct early_suspend msm_thermal_early_suspend_handler = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN,
	.suspend = msm_thermal_early_suspend,
	.resume = msm_thermal_late_resume,
};

static int __init msm_thermal_init(void)
{
	int rc, ret = 0;

	enabled = 1;
        check_temp_workq = alloc_workqueue(
                "msm_thermal", WQ_UNBOUND | WQ_RESCUER, 1);
        if (!check_temp_workq)
                BUG_ON(ENOMEM);
        INIT_DELAYED_WORK(&check_temp_work, check_temp);
        queue_delayed_work(check_temp_workq, &check_temp_work, 0);

	msm_thermal_kobject = kobject_create_and_add("msm_thermal", kernel_kobj);
	if (msm_thermal_kobject) {
		rc = sysfs_create_group(msm_thermal_kobject,
							&msm_thermal_attr_group);
		if (rc) {
			pr_warn("msm_thermal: sysfs: ERROR, could not create sysfs group");
		}
	} else
		pr_warn("msm_thermal: sysfs: ERROR, could not create sysfs kobj");

        register_early_suspend(&msm_thermal_early_suspend_handler);

	return ret;
}
fs_initcall(msm_thermal_init);

