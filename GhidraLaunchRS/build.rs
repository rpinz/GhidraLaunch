// build.rs

extern crate embed_resource;

fn main() {
  embed_resource::compile("..\\Resources\\Resource.rc", embed_resource::NONE)
    .manifest_required()
    .expect("failed to compile Windows resources");
}
