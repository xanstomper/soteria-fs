pub mod entropy_sensor;
pub mod key_access_sensor;
pub mod process_sensor;
pub mod write_sensor;

pub trait Sensor {
    fn name(&self) -> &'static str;
}
