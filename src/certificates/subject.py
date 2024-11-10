class Subject(dict):
    def __init__(
        self,
        common_name: str,
        country_name: str = "US",
        state_or_province_name: str = "",
        locality_name: str = "",
        organization_name: str = "",
        email: str = "",
    ):
        super().__init__(
            common_name=common_name,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
            organization_name=organization_name,
            email=email,
        )
