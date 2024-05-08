use crate::scan::{compute_file_hashes, remove_files, ScanError, INFECTED_HASHES};
use dashmap::DashMap;
use egui::mutex::RwLock;
use egui::{Color32, ProgressBar};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct TemplateApp {
    pub launcher: Launcher,
    pub selected_path: Option<PathBuf>,

    #[serde(skip)]
    pub scanning: bool,
    #[serde(skip)]
    pub total_count: Arc<AtomicI32>,
    #[serde(skip)]
    pub current_progress: Arc<AtomicI32>,
    #[serde(skip)]
    pub scan_result: Arc<DashMap<String, PathBuf>>,
    #[serde(skip)]
    pub scan_status: Arc<AtomicBool>,
    #[serde(skip)]
    pub current_error: Arc<RwLock<Option<ScanError>>>,
}

#[derive(PartialEq, serde::Deserialize, serde::Serialize)]
pub enum Launcher {
    Modrinth,
    Prism,
    #[allow(clippy::enum_variant_names)]
    ATLauncher,
    Vanilla,
    CustomDirectory,
}

impl Launcher {
    fn get_data_directory(&self) -> Option<PathBuf> {
        match self {
            Launcher::Modrinth => {
                dirs::config_dir().map(|x| x.join("com.modrinth.theseus").join("profiles"))
            }
            Launcher::Prism => {
                dirs::config_dir().map(|x| x.join("PrismLauncher").join("instances"))
            }
            Launcher::ATLauncher => dirs::config_dir().map(|x| x.join("ATLauncher")),
            Launcher::Vanilla => dirs::config_dir().map(|x| x.join(".minecraft")),
            Launcher::CustomDirectory => None,
        }
    }
}

impl Default for TemplateApp {
    fn default() -> Self {
        Self {
            launcher: Launcher::Modrinth,
            selected_path: None,
            scanning: false,
            total_count: Arc::new(AtomicI32::new(0)),
            current_progress: Arc::new(AtomicI32::new(0)),
            scan_result: Arc::new(DashMap::new()),
            scan_status: Arc::new(AtomicBool::new(false)),
            current_error: Arc::new(RwLock::new(None)),
        }
    }
}

impl TemplateApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        if let Some(storage) = cc.storage {
            return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        }

        Default::default()
    }
}

impl eframe::App for TemplateApp {
    /// Called by the frame work to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // The central panel the region left after adding TopPanel's and SidePanel's
            ui.heading("modrinth scanner");

            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                ui.label("What Minecraft Launcher do you use?");
                ui.selectable_value(&mut self.launcher, Launcher::Modrinth, "Modrinth App");
                ui.selectable_value(&mut self.launcher, Launcher::Prism, "Prism Launcher");
                ui.selectable_value(&mut self.launcher, Launcher::ATLauncher, "ATLauncher");
                ui.selectable_value(&mut self.launcher, Launcher::Vanilla, "Vanilla");
                ui.selectable_value(&mut self.launcher, Launcher::CustomDirectory, "Custom directory");
            });
            ui.add_space(10.0);
            ui.end_row();

            if self.launcher == Launcher::CustomDirectory {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Select directory: ");
                    if ui.button("Open folder...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.selected_path = Some(path);
                        }
                    }
                });
                ui.end_row();
            }

            let path = if let Some(path) = self.launcher.get_data_directory() {
                Some(path)
            } else {
                self.selected_path.clone()
            };

            if let Some(path) = path {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Selected path: ");
                    ui.strong(path.display().to_string());

                    if (!self.scanning && !self.scan_status.load(Ordering::Relaxed)) && ui.button("Begin scan").clicked() {
                        self.scanning = true;
                        self.scan_result = Arc::new(DashMap::new());

                        let current_progress = self.current_progress.clone();
                        let total_count = self.total_count.clone();
                        let scan_result = self.scan_result.clone();
                        let scan_status = self.scan_status.clone();
                        let current_error = self.current_error.clone();

                        std::thread::spawn(move || {
                            match compute_file_hashes(path.as_path(), current_progress, total_count) {
                                Ok(res) => {
                                    for (key, val) in res {
                                        if INFECTED_HASHES.contains(&&*key) {
                                            scan_result.insert(key, val);
                                        }
                                    }
                                }
                                Err(err) => {
                                    *current_error.write() = Some(err);
                                }
                            }
                            scan_status.store(true, Ordering::SeqCst);
                        });
                    }
                });
            }

            if let Some(val) = self.current_error.read().as_ref() {
                ui.add_space(10.0);
                ui.colored_label(Color32::RED, format!("Error scanning: {}", val));
                ui.add_space(10.0);
            }
            else if self.scan_status.load(Ordering::Relaxed) {
                ui.add_space(10.0);
                ui.label("Scan complete!");
                ui.add_space(10.0);

                if self.scan_result.is_empty() {
                    ui.colored_label(Color32::GREEN, "No malicious content found!");
                } else {
                    ui.colored_label(Color32::RED, "Malware found at paths below:");
                    ui.vertical(|ui| {
                        for val in self.scan_result.iter() {
                            ui.spacing_mut().item_spacing.y = 5.0;
                            ui.label(val.value().display().to_string());
                        }
                    });

                    if ui.button("Remove files").clicked() {
                        let current_error = self.current_error.clone();
                        let paths = self.scan_result.iter().map(|x| x.value().clone()).collect();

                        std::thread::spawn(move || {
                            if let Err(err) = remove_files(paths) {
                               *current_error.write() = Some(err);
                                }

                        });
                    }

                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.colored_label(Color32::RED, "Malware has been detected on your computer. We recommend changing all passwords for all accounts signed in on this computer and saved in browsers (including apps like Discord). Check out the ");
                        ui.hyperlink_to("blog post", "https://github.com/modrinth/oracle");
                        ui.colored_label(Color32::RED, " for more information.");

                    });
                }
            } else if self.scanning {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Scanning... ");

                    let (progress, text) = {
                        let current = self.current_progress.load(Ordering::Relaxed);
                        let total = self.total_count.load(Ordering::Relaxed);
                        let text = format!("{}/{}", current, total);
                        (current as f32 / total as f32, text)
                    };

                    ui.strong(text);

                    ui.add(ProgressBar::new(progress));
                });
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                copyright_and_source(ui);
                egui::widgets::global_dark_light_mode_buttons(ui);
            });
        });
    }
}

fn copyright_and_source(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label("© Rinth, Inc. ");
        ui.hyperlink_to("Source code.", "https://github.com/modrinth/oracle");
    });
}
