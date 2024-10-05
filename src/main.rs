use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::{invoke},
    program_error::ProgramError,
    pubkey::Pubkey,
};
use std::convert::TryInto;

use borsh::{BorshDeserialize, BorshSerialize};
use spl_token::{
    instruction::{mint_to, transfer, burn},
    state::Mint,
};
use solana_program::program_pack::Pack;

#[derive(Default, BorshSerialize, BorshDeserialize, Debug)]
pub struct TokenConfig {
    pub max_supply: u64,
    pub initialized: bool,
    pub admin_pubkey: Pubkey,
}

pub enum CustomError {
    MaxSupplyExceeded = 0x1,
}

impl From<CustomError> for ProgramError {
    fn from(e: CustomError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (instruction, rest_of_data) = instruction_data.split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match instruction {
        0 => process_transfer(accounts, rest_of_data),
        1 => process_mint(accounts, rest_of_data, program_id),
        2 => process_burn(accounts, rest_of_data),
        3 => {  
            if rest_of_data.len() < 40 {
                return Err(ProgramError::InvalidInstructionData);
            }

            let admin_pubkey: Pubkey = Pubkey::new_from_array(
                rest_of_data[..32].try_into().map_err(|_| ProgramError::InvalidInstructionData)?
            );
            let max_supply: u64 = u64::from_le_bytes(
                rest_of_data[32..40].try_into().map_err(|_| ProgramError::InvalidInstructionData)?
            );

            process_initialize(accounts, admin_pubkey, max_supply)
        },
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_initialize(
    accounts: &[AccountInfo],
    admin_pubkey: Pubkey,
    max_supply: u64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let config_account = next_account_info(account_info_iter)?;

    let mut config_data = config_account.try_borrow_mut_data()?;
    let mut token_config = TokenConfig::try_from_slice(&config_data).map_err(|_| ProgramError::InvalidAccountData)?;

    if token_config.initialized {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    token_config.admin_pubkey = admin_pubkey;
    token_config.max_supply = max_supply;
    token_config.initialized = true;

    token_config.serialize(&mut *config_data)?;

    msg!("Token initialized with admin: {} and max supply: {}", admin_pubkey, max_supply);

    Ok(())
}

fn process_transfer(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let from_account = next_account_info(account_info_iter)?;
    let to_account = next_account_info(account_info_iter)?;
    let authority = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;

    let amount = u64::from_le_bytes(instruction_data.try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
    if amount == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    msg!("Transferring {} tokens", amount);
    let transfer_ix = transfer(
        token_program.key,
        from_account.key,
        to_account.key,
        authority.key,
        &[],
        amount,
    )?;

    invoke(&transfer_ix, &[from_account.clone(), to_account.clone(), authority.clone()])?;
    Ok(())
}

fn process_mint(accounts: &[AccountInfo], instruction_data: &[u8], _program_id: &Pubkey) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let mint_account = next_account_info(account_info_iter)?;
    let destination_account = next_account_info(account_info_iter)?;
    let mint_authority = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;
    let config_account = next_account_info(account_info_iter)?;

    let amount = u64::from_le_bytes(instruction_data.try_into().map_err(|_| ProgramError::InvalidInstructionData)?);

    let config_data = config_account.try_borrow_data()?;
    let token_config: TokenConfig = TokenConfig::try_from_slice(&config_data).map_err(|_| ProgramError::InvalidAccountData)?;

    if *mint_authority.key != token_config.admin_pubkey {
        msg!("Unauthorized: Only the admin can mint tokens.");
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mint_state = Mint::unpack(&mint_account.try_borrow_data()?)?;
    let current_supply = mint_state.supply;

    if current_supply + amount > token_config.max_supply {
        msg!("Minting would exceed max supply limit of {}", token_config.max_supply);
        return Err(CustomError::MaxSupplyExceeded.into());
    }

    msg!("Minting {} tokens", amount);
    let mint_ix = mint_to(
        token_program.key,
        mint_account.key,
        destination_account.key,
        mint_authority.key,
        &[],
        amount,
    )?;

    invoke(&mint_ix, &[mint_account.clone(), destination_account.clone(), mint_authority.clone()])?;
    Ok(())
}

fn process_burn(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let burn_account = next_account_info(account_info_iter)?;
    let mint_account = next_account_info(account_info_iter)?;
    let burn_authority = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;

    let amount = u64::from_le_bytes(instruction_data.try_into().map_err(|_| ProgramError::InvalidInstructionData)?);

    msg!("Burning {} tokens", amount);
    let burn_ix = burn(
        token_program.key,
        burn_account.key,
        mint_account.key,
        burn_authority.key,
        &[],
        amount,
    )?;

    invoke(&burn_ix, &[burn_account.clone(), mint_account.clone(), burn_authority.clone()])?;
    Ok(())
}

entrypoint!(process_instruction);
