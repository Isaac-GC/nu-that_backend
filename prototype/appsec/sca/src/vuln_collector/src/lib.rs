use std::io::Read;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zip::ZipArchive;
use serde_json::from_str;
use self::schema::OvfFormat;

mod schema {
    pub struct OvfFormat;
}

type Error = Box<dyn std::error::Error>;

// const BASE_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";
const BUCKET_NAME: &str = "osv-vulnerabilities";
const BASE_API_URL: &str = "https://storage.googleapis.com/storage/v1/b/";

// ToDo
// - Write function to download zip file [Done]
// - Write function to check for updated files
// - Write function to check/Mirror NIST NVD database

// Setup the structure of the returned JSON (Google Bucket Object)
#[derive(Debug, Serialize, Deserialize)]
struct BucketObject {
    name: String,
    #[serde(rename = "timeCreated")]
    time_created: String,
    updated: String,
}


// Response of the object list
#[derive(Debug, Serialize, Deserialize)]
struct BucketObjectList {
    kind: String,
    #[serde(rename = "nextPageToken")]
    nextpagetoken: Option<String>,
    prefixes: Vec<String>,
    items: Vec<BucketObject>,
}


#[derive(Debug, Serialize, Deserialize)]
struct VulnListing {
    // List of the vulnerabilities in OVF Format
    vulnerabilities: Option<Vec<OvfFormat>>,
    // epoch time of when last updated
    last_updated: Option<i64>,
    // Package type (PyPI, NPM, Go)
    package_type: String,

}


// TODO: 
// - Finish writing out impl function
// - Rewrite other functions
//   - fetch osv's
//   - extract_osv_data
//   - retrieve updated files 14400


impl VulnListing {
    pub fn init(&self, package_type) {
        &self.package_type = package_type;
        &self.last_updated = 0; // set to 0 
    }


    pub fn check_for_updates(&self) {
        let mut current_datetime: i64 = Utc::now().timestamp_opt();
        match current_datetime.single() { 
            Some(x) => current_datetime = x,
            None => println("Error getting the Current epoch datetime"),
        };
        // Check to see if at least 4 hours have passed. Used to rate limit
        if ( (current_datetime - &self.last_updated) > 14400 ) {

        } else {
            return 
        }
    }

    async fn fetch_osv_vuln_list_zip(&self) {
        let object_url = [package_type, "all.zip"].join("%2f");
        let vuln_list_url = [
            BASE_API_URL,
            BUCKET_NAME,
            "o",
            &object_url
        ].join("/");

        // Get the object as byte object. Used later to extract as a zip file
        let response = reqwest::get(vuln_list_url).await?.bytes().await?; 
        let buffer = response.to_vec();
        Ok(buffer)
    }

    async fn extract_osv_json_data(json_byte_data: Vec<u8>) -> Result<Vec<OvfFormat>, Error> {
        let reader = std::io::Cursor::new(&json_byte_data);
        let mut archive = ZipArchive::new(reader).unwrap();
        let mut json_vec = Vec::new();

         // Get the number of files and extract them in memory to json documents
        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i).unwrap();
            let mut json_data_buffer = String::new();

            zip_file.read_to_string(&mut json_data_buffer)?;
            let ovfdoc: OvfFormat = from_str(&json_data_buffer);
            
            json_vec.push(ovfdoc);
        }

        Ok(json_vec)
    }
}

// Function is/should only be called during the initialization of the application
//   subsequent calls could be noisy and high-bandwidth usage.
// pub async fn fetch_osv_vuln_list_zip(package_type: &str) -> Result<Vec<u8>, Error> {
//     let object_url_encoded_path = [package_type, "all.zip"].join("%2F");
//     let url = [BASE_API_URL, BUCKET_NAME, "o", &object_url_encoded_path].join("/");
//     let response = reqwest::get(url).await?.bytes().await?;
//     let buffer = response.to_vec();

//     Ok(buffer)
// }


// Function should only be called in conjuction with the 'fetch_osv_vuln_list_zip' function.
// pub async fn extract_osv_json_data(json_byte_data: Vec<u8>) -> Result<Vec<OvfFormat>, Error> {
//     let reader = std::io::Cursor::new(&json_byte_data);
//     let mut archive = ZipArchive::new(reader).unwrap();
//     let mut json_vec = Vec::new();

//     // Get the number of files and extract them in memory to json documents
//     for i in 0..archive.len() {
//         let mut zip_file = archive.by_index(i).unwrap(); 
//         let mut jd_buffer = String::new();

//         zip_file.read_to_string(&mut jd_buffer)?;
//         let ovfdoc: OvfFormat = from_str(&jd_buffer)?;
//         println!("{:?}", &ovfdoc);

//         json_vec.push(ovfdoc);        
//     }

//     Ok(json_vec)
// }



// Function should be used for subsequent calls. It will only update files if the modified date is newer than the
//   last_epoch_update value, or if there are new files with a created time newer than the last_epoch_update value
pub async fn check_for_updated_files(package_type: &str, last_epoch_update: i64) -> Result<Vec<OvfFormat>, Error> {

    let url: String = [BASE_API_URL, BUCKET_NAME, "o", package_type, "?fields=name,timeCreated,updated,id"].join("/");
    let current_datetime: i64 = Utc::now().timestamp_opt();
    let resultlist: Vec<String> = retrieve_list(url, current_datetime).await?;
    let itemresults: Vec<OvfFormat> = retrieve_obj_from_list(resultlist).await?;

    

    // Retrieve a list of objects and returns a list of Strings for files that need to be updated
    async fn retrieve_list(url: String, current_datetime: i64) -> Result<Vec<String>, Error> {
        let mut templist: Vec<String> = Vec::new();
        let mut objlist: Vec<BucketObjectList> = Vec::new();
        // let mut token_present = true;

        // while token_present {
            let response = reqwest::get(url).await?.text().await?;
            let objects: BucketObjectList  = from_str(&response)?;
            // let mut token_present: bool = true;
            objlist.push(objects);
            
        //     if let None = objects.nextpagetoken { break; }
        // }

        for obj in objlist.iter() {
            for item in obj.items.iter() {
                let epoch_time_created = DateTime::parse_from_rfc2822(&item.time_created)?.timestamp();
                let epoch_time_updated = DateTime::parse_from_rfc2822(&item.updated)?.timestamp();

                // This needs to be improved -- would be better to get the/a stored time
                if (last_epoch_update < epoch_time_created) ||
                    (last_epoch_update < epoch_time_updated) {
                        templist.push(item.name.to_string());
                }
            }
        }
        return Ok(templist)
    }

    // Uses a list of Strings to automatically download files and then return 
    //   a list of formatted documents to be consumed
    async fn retrieve_obj_from_list(templist: Vec<String>) -> Result<Vec<OvfFormat>, Error>{
        let mut result_list: Vec<OvfFormat> = Vec::new();
        let mut url = [BASE_API_URL, BUCKET_NAME, "o"].join("/");
        for item in templist {
            url += &format!("/{}?alt=media", &item);
            let response: String = reqwest::get(&url).await?.text().await?;

            let ovfdoc: OvfFormat = from_str(&response)?;
            result_list.push(ovfdoc); 
        }

        Ok(result_list)
    }



    Ok(itemresults)
}