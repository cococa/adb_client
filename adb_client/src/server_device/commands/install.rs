use std::{fs::File, io::Read, path::Path};

use crate::{
    Result,
    models::{ADBCommand, ADBLocalCommand},
    server_device::ADBServerDevice,
    utils::check_extension_is_apk,
};

impl ADBServerDevice {
    /// Install an APK on device
    pub fn install<P: AsRef<Path>>(&mut self, apk_path: P, user: Option<&str>) -> Result<()> {
        self.install_with_options(apk_path, user, &[])
    }

    /// Install an APK using the streamed ADB install protocol with the
    /// package-manager flags accepted by the compatibility CLI.
    pub fn install_with_options<P: AsRef<Path>>(
        &mut self,
        apk_path: P,
        user: Option<&str>,
        flags: &[String],
    ) -> Result<()> {
        let mut apk_file = File::open(&apk_path)?;

        check_extension_is_apk(&apk_path)?;

        let file_size = apk_file.metadata()?.len();

        self.set_serial_transport()?;

        // Official modern ADB first uses abb_exec. It bypasses shell parsing
        // and is observably treated differently by some vendor security
        // layers. Older devices reject the service before any bytes are sent,
        // so safely fall back to the regular streamed install command.
        let mut abb_arguments = vec!["package".to_owned(), "install".to_owned()];
        if let Some(user) = user {
            abb_arguments.extend(["--user".to_owned(), user.to_owned()]);
        }
        abb_arguments.extend(flags.iter().cloned());
        abb_arguments.extend(["-S".to_owned(), file_size.to_string()]);
        let command = ADBCommand::Local(ADBLocalCommand::AbbExec(abb_arguments));
        if self.transport.send_adb_request(&command).is_ok() {
            eprintln!("[adb_client] installing through abb_exec");
        } else {
            eprintln!("[adb_client] abb_exec unavailable; using streamed install fallback");
            self.set_serial_transport()?;
            self.transport
                .send_adb_request(&ADBCommand::Local(ADBLocalCommand::Install(
                    file_size,
                    user.map(ToString::to_string),
                    flags.to_vec(),
                )))?;
        }

        let mut raw_connection = self.transport.get_raw_connection()?;

        std::io::copy(&mut apk_file, &mut raw_connection)?;

        let mut data = [0; 1024];
        let read_amount = self.transport.get_raw_connection()?.read(&mut data)?;

        match &data[0..read_amount] {
            b"Success\n" => {
                log::info!(
                    "APK file {} successfully installed",
                    apk_path.as_ref().display()
                );
                Ok(())
            }
            d => Err(crate::RustADBError::ADBRequestFailed(String::from_utf8(
                d.to_vec(),
            )?)),
        }
    }
}
