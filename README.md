# survivor_pool
Flask website for creating betting pools for popular American reality television show, Survivor.


## Database

```mermaid
---
title: Survivor Pool
---

erDiagram
    settings{
        integer id
        integer current_season
    }
   pool{
    integer id
    text pool_name
    text pool_slug
    text password_hash

    text pool_type
    real multiplier
    integer num_picks
    real dollar_buy_in
    int payout_places
    text payout_dict


    integer season
   }
   user }|--|{ user_pool_map : ""
   user_pool_map }|--|{ pool : ""

   user_pool_map {
    int user_id
    int pool_id
    boolean is_admin
   }
   
   user{
    integer id
    text name
    text email
    text password_hash
    boolean is_site_admin
   }

   user_pool_map }|--|{ pick : ""
   pick{
    integer user_pool_map_id
    integer contestant_id
   }
    contestant{
        integer id
        text name
        text image_path
        integer left_show_in_episode
        integer season
    }

    pick }|--|{ contestant : "" 
    pool ||--|{ invite_token : ""
    invite_token {
        integer id
        integer pool_id
        text token
        boolean active
    }
```

database tables

CREATE TABLE user (
    id INTEGER
)
