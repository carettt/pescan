use criterion::{black_box, criterion_group, criterion_main, Criterion};

use std::process::Command;
use std::time::Duration;

fn main_process(c: &mut Criterion) {
  c.bench_function("main_baseline", |b| {
    b.iter(|| {
      let process = Command::new("cargo")
        .args(["run", "--release", "--",
        "../wk4/Sample2/ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9.exe"])
        .output().expect("Failed to execute process");

      black_box(process);
    });
  });

  let mut all_group = c.benchmark_group("all_details");

  all_group.bench_function("txt", |b| {
    b.iter(|| {
      let process = Command::new("cargo")
        .args(["run", "--release", "--", "-A",
        "../wk4/Sample2/ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9.exe"])
        .output().expect("Failed to execute process");

      black_box(process);
    });
  });

  all_group.bench_function("json", |b| {
    b.iter(|| {
      let process = Command::new("cargo")
        .args(["run", "--release", "--",
          "-A", "-f json",
        "../wk4/Sample2/ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9.exe"])
        .output().expect("Failed to execute process");

      black_box(process);
    });
  });

  all_group.bench_function("yaml", |b| {
    b.iter(|| {
      let process = Command::new("cargo")
        .args(["run", "--release", "--",
          "-A", "-f yaml",
        "../wk4/Sample2/ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9.exe"])
        .output().expect("Failed to execute process");

      black_box(process);
    });
  });

  all_group.bench_function("toml", |b| {
    b.iter(|| {
      let process = Command::new("cargo")
        .args(["run", "--release", "--",
          "-A", "-f toml",
        "../wk4/Sample2/ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9.exe"])
        .output().expect("Failed to execute process");

      black_box(process);
    });
  });

  all_group.bench_function("csv", |b| {
    b.iter(|| {
      let process = Command::new("cargo")
        .args(["run", "--release", "--",
          "-A", "-f csv",
        "../wk4/Sample2/ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9.exe"])
        .output().expect("Failed to execute process");

      black_box(process);
    });
  });

  all_group.finish();
}

criterion_group!{
  name = benches;
  config = Criterion::default()
    .measurement_time(Duration::from_secs(12));
  targets = main_process
}
criterion_main!(benches);
