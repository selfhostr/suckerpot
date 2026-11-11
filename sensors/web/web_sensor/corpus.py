"""Generated site copy for the fake WordPress site.

Titles, taglines, post titles and post bodies are composed from small fragment pools with a
seeded generator, so each deployment gets its own text and no sentence is shared by a whole
fleet. The result reads like the blog of a small local business.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class Trade:
    kind: str  # "dental", "bakery"...
    suffixes: tuple[str, ...]  # the part of a business name that says what it does
    offers: tuple[str, ...]  # things the business does or sells (noun phrases)
    audiences: tuple[str, ...]
    taglines: tuple[str, ...]  # tagline stems; "{aud}" is filled with an audience


TRADES: tuple[Trade, ...] = (
    Trade(
        "dental",
        ("Dental", "Dental Care", "Dentistry", "Smile Clinic"),
        ("check-ups", "hygiene visits", "whitening sessions", "children's appointments"),
        ("the whole family", "nervous patients", "busy parents"),
        ("Gentle care for {aud}", "Modern dentistry for {aud}", "Friendly appointments for {aud}"),
    ),
    Trade(
        "bakery",
        ("Bakery", "Crumb", "Bread Co.", "Patisserie"),
        ("sourdough loaves", "seasonal tarts", "morning pastries", "celebration cakes"),
        ("early risers", "the neighbourhood", "office parties"),
        ("Fresh bread for {aud}", "Baked every morning for {aud}", "Small batches, made for {aud}"),
    ),
    Trade(
        "cycles",
        ("Cycles", "Bike Shop", "Bicycle Works", "Cycle Repair"),
        ("service slots", "rental bikes", "wheel builds", "group rides"),
        ("commuters", "weekend riders", "families"),
        ("Repairs and rentals for {aud}", "Local rides, honest repairs for {aud}"),
    ),
    Trade(
        "yoga",
        ("Yoga", "Studio", "Movement", "Pilates"),
        ("morning classes", "evening classes", "beginner courses", "weekend workshops"),
        ("every level", "new mothers", "office workers"),
        ("Classes for {aud}", "Calm, steady practice for {aud}"),
    ),
    Trade(
        "accounting",
        ("Accounting", "Tax Services", "Bookkeeping", "Financial"),
        ("tax returns", "payroll runs", "year-end accounts", "VAT filings"),
        ("small business", "sole traders", "local shops"),
        ("Straightforward numbers for {aud}", "Clear advice for {aud}"),
    ),
    Trade(
        "landscaping",
        ("Landscaping", "Gardens", "Garden Design", "Lawn Care"),
        ("spring clean-ups", "hedge trimming", "patio builds", "planting schemes"),
        ("busy homeowners", "small gardens", "local landlords"),
        ("Gardens that last for {aud}", "Outdoor spaces for {aud}"),
    ),
    Trade(
        "photography",
        ("Photography", "Studio", "Portraits", "Images"),
        ("portrait sessions", "wedding days", "family shoots", "product photos"),
        ("couples", "growing families", "local makers"),
        ("Portraits and stories for {aud}", "Honest photographs for {aud}"),
    ),
    Trade(
        "realty",
        ("Realty", "Properties", "Estates", "Homes"),
        ("viewings", "valuations", "open days", "rental listings"),
        ("first-time buyers", "growing families", "landlords"),
        ("Homes with a view for {aud}", "Local property advice for {aud}"),
    ),
    Trade(
        "plumbing",
        ("Plumbing", "Heating", "Plumbing & Heating", "Pipe Works"),
        ("boiler services", "bathroom fits", "emergency call-outs", "leak checks"),
        ("homeowners", "landlords", "small offices"),
        ("Reliable plumbers for {aud}", "Warm homes for {aud}"),
    ),
    Trade(
        "florist",
        ("Flowers", "Florist", "Blooms", "Flower Shop"),
        ("wedding bouquets", "weekly deliveries", "funeral tributes", "seasonal wreaths"),
        ("neighbours", "event planners", "gift givers"),
        ("Fresh flowers for {aud}", "Seasonal blooms for {aud}"),
    ),
    Trade(
        "physio",
        ("Physio", "Physiotherapy", "Health Clinic", "Wellness"),
        ("first assessments", "sports massage", "rehab programmes", "posture clinics"),
        ("active people", "office workers", "older adults"),
        ("Movement and recovery for {aud}", "Practical treatment for {aud}"),
    ),
    Trade(
        "garage",
        ("Garage", "Motors", "Auto Care", "Tyres & Service"),
        ("annual services", "tyre changes", "MOT preparation", "brake checks"),
        ("local drivers", "small fleets", "first-time owners"),
        ("Honest car care for {aud}", "Servicing you can trust for {aud}"),
    ),
)
PLACES = (
    "Lakeside", "Riverside", "Northgate", "Hillcrest", "Harbor View", "Oakline", "Westfield",
    "Maple", "Cedar", "Brookfield", "Stonebridge", "Elmwood", "Greenway", "Fairview", "Ashford",
    "Pinewood", "Millbrook", "Kingsway", "Redwood", "Summit", "Willow", "Bayside", "Highfield",
)  # fmt: skip
SURNAMES = (
    "Moreau", "Keller", "Brandt", "Fischer", "Novak", "Larsen", "Weber", "Costa", "Hartmann",
    "Meyer", "Rossi", "Lindqvist", "Okafor", "Dubois", "Schmid", "Kovacs", "Haas", "Bianchi",
)  # fmt: skip
ADJECTIVES = (
    "Blue", "Quiet", "Golden", "Little", "Bright", "Old Town", "Wild", "Honest", "Silver", "True",
)  # fmt: skip

_TITLES = (
    "{Season} opening hours", "New website, same friendly team", "Meet the team",
    "Our {season} newsletter", "Thank you for a great {period}", "What to expect at your first visit",
    "Holiday schedule", "A look behind the scenes", "We are hiring", "{Offer} now available",
    "Booking tips for {season}", "Prices for {year}", "Notes from the {kind} counter",
    "Closed for {days} days", "Why we love {offer}", "Questions we hear most often",
    "A busy {season} ahead", "Open evenings are back", "Gift vouchers", "Changes to our {offer}",
)  # fmt: skip
_OPEN = (
    "We are pleased to share", "A quick note for our regular customers:", "Just so you know,",
    "Over the last few weeks", "After many requests,", "Following your feedback,",
    "From the team here,", "This month", "Starting next week,", "If you have been wondering,",
)  # fmt: skip
_MID = (
    "our {offer} are now available on {weekday}s and {weekday2}s from {h1} to {h2}",
    "we have extended the slots for {offer} by {n} places each week",
    "{offer} will move to a new booking system, so please check the times before you come",
    "we will be adding {offer} for {aud} throughout the {season}",
    "the waiting list for {offer} is down to about {n} days",
    "we are trialling a quieter hour for {offer} on {weekday} mornings",
    "prices for {offer} stay the same until the end of {month}",
    "a few spaces for {offer} have opened up in {month}",
)  # fmt: skip
_CLOSE = (
    "Call us or send a message if you would like to book.",
    "Drop by the shop and ask for {first}, who is happy to help.",
    "As always, thank you for supporting a local business.",
    "Questions are welcome, just use the contact form.",
    "We will post any further changes here.",
    "Walk-ins are fine, but a message first helps us plan.",
    "{first} will reply to every message within a working day.",
    "See you soon!",
)  # fmt: skip
_SEASONS = ("spring", "summer", "autumn", "winter")
_MONTHS = (
    "January", "February", "March", "April", "May", "June", "July", "August", "September",
    "October", "November", "December",
)  # fmt: skip
_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
_FIRSTS = (
    "Daniel", "Sarah", "Michael", "Laura", "Thomas", "Julia", "Marc", "Elena", "Peter", "Nina",
    "Anna", "Lukas", "Sofia", "David", "Clara", "Jonas", "Maya", "Felix",
)  # fmt: skip


def first_names() -> tuple[str, ...]:
    return _FIRSTS


def pick_trade(rng: random.Random) -> Trade:
    return rng.choice(TRADES)


def site_identity(rng: random.Random, trade: Trade) -> tuple[str, str]:
    """(title, tagline). Ampersands are HTML-escaped, as WordPress renders the title."""
    suffix = rng.choice(trade.suffixes)
    style = rng.randrange(4)
    if style == 0:
        name = f"{rng.choice(PLACES)} {suffix}"
    elif style == 1:
        name = f"{rng.choice(SURNAMES)} & {rng.choice(SURNAMES)} {suffix}"
    elif style == 2:
        name = f"{rng.choice(ADJECTIVES)} {rng.choice(PLACES)} {suffix}"
    else:
        name = f"The {rng.choice(PLACES)} {suffix}"
    tagline = rng.choice(trade.taglines).format(aud=rng.choice(trade.audiences))
    return name.replace("&", "&amp;"), tagline.replace("&", "&amp;")


def _fill(text: str, rng: random.Random, trade: Trade, year: int) -> str:
    season = rng.choice(_SEASONS)
    h1 = rng.randrange(7, 12)
    return text.format(
        offer=rng.choice(trade.offers),
        aud=rng.choice(trade.audiences),
        kind=trade.kind,
        season=season,
        Season=season.capitalize(),
        period=rng.choice(("year", "season", "quarter")),
        year=year,
        month=rng.choice(_MONTHS),
        weekday=rng.choice(_WEEKDAYS[:3]),
        weekday2=rng.choice(_WEEKDAYS[3:]),
        h1=f"{h1}:{rng.choice(('00', '30'))}",
        h2=f"{rng.randrange(15, 20)}:{rng.choice(('00', '30'))}",
        n=rng.randrange(2, 9),
        days=rng.randrange(2, 6),
        first=rng.choice(_FIRSTS),
        Offer=rng.choice(trade.offers).capitalize(),
    )


def compose_post(rng: random.Random, trade: Trade, year: int) -> tuple[str, str]:
    """(title, body) for one post: a title template and two or three composed sentences."""
    title = _fill(rng.choice(_TITLES), rng, trade, year)
    sentences = []
    for _ in range(rng.randrange(1, 3)):
        sentences.append(
            f"{_fill(rng.choice(_OPEN), rng, trade, year)} {_fill(rng.choice(_MID), rng, trade, year)}."
        )
    sentences.append(_fill(rng.choice(_CLOSE), rng, trade, year))
    return title, " ".join(sentences)
