use rand::Rng;

pub fn generate_unique_number(n:i32)->String{
   let  numbers = "0123456789";
    let mut rng = rand::thread_rng();
    let unique_number:String = (0..n).map(|_|{
        numbers.chars().nth(rng.gen_range(0..numbers.len())).unwrap()
    }).collect();
    unique_number
}


#[cfg(test)]
mod test{
    #[test]
    fn test_generate_unique_number(){
        let rns = super::generate_unique_number(18);
        println!("生成18位随机数:{}",rns);
    }
}