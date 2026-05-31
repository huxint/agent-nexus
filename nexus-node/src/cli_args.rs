pub(crate) fn required_arg<'a>(
    args: &'a [String],
    index: usize,
    flag: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value").into())
}

pub(crate) fn parse_u64_arg(value: &str, flag: &str) -> Result<u64, Box<dyn std::error::Error>> {
    value
        .parse::<u64>()
        .map_err(|err| format!("invalid {flag}: {err}").into())
}

pub(crate) fn parse_usize_arg(
    value: &str,
    flag: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    value
        .parse::<usize>()
        .map_err(|err| format!("invalid {flag}: {err}").into())
}

pub(crate) fn parse_i32_arg(value: &str, flag: &str) -> Result<i32, Box<dyn std::error::Error>> {
    value
        .parse::<i32>()
        .map_err(|err| format!("invalid {flag}: {err}").into())
}

pub(crate) fn parse_env_assignment(
    value: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "invalid --env, expected KEY=VALUE".to_string())?;
    if key.is_empty() {
        return Err("invalid --env, key cannot be empty".into());
    }
    Ok((key.to_string(), value.to_string()))
}

pub(crate) fn normalize_symbol(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
